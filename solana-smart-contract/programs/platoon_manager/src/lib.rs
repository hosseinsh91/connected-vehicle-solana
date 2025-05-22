use anchor_lang::prelude::*;
use vehicle_node_chain::cpi::accounts::JoinPlatoonAndShareData;
use vehicle_node_chain::program::VehicleNodeChain;

declare_id!("");

// Store server pubkey in a modifiable state account instead of hardcoding
#[account]
pub struct PlatoonConfig {
    pub global_server_pubkey: Pubkey,
    pub admin: Pubkey,
}

// Constants to avoid magic numbers
pub const MAX_MEMBERS: usize = 100;
pub const MAX_RSU_ID_LENGTH: usize = 1004;

// Define MemberInfo at the outer scope so it can be used by Platoon
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, Default)]
pub struct MemberInfo {
    pub vehicle_id: String,
    pub trust_score: u8,
}

#[program]
pub mod platoon_manager {
    use super::*;

    pub fn initialize_config(ctx: Context<InitializeConfig>, global_server: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.global_server_pubkey = global_server;
        config.admin = ctx.accounts.admin.key();
        Ok(())
    }

    pub fn update_global_server(ctx: Context<UpdateConfig>, new_global_server: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        // Only admin can update this
        require!(ctx.accounts.admin.key() == config.admin, PlatoonError::Unauthorized);
        config.global_server_pubkey = new_global_server;
        Ok(())
    }

    pub fn initialize_platoon(
        ctx: Context<InitializePlatoon>,
        rsu_id: String,
        trust_threshold: u8,
    ) -> Result<()> {
        // Validate rsu_id
        require!(!rsu_id.is_empty() && rsu_id.len() <= MAX_RSU_ID_LENGTH, PlatoonError::InvalidInput);

        let platoon = &mut ctx.accounts.platoon;
        platoon.rsu_id = rsu_id;
        platoon.trust_threshold = trust_threshold;
        platoon.created_by = ctx.accounts.creator.key();
        platoon.members = Vec::new();
        platoon.total_rewards = 0;
        Ok(())
    }

    pub fn update_threshold(ctx: Context<UpdateThreshold>, new_threshold: u8) -> Result<()> {
        let platoon = &mut ctx.accounts.platoon;
        require!(
            ctx.accounts.creator.key() == platoon.created_by,
            PlatoonError::Unauthorized
        );
        platoon.trust_threshold = new_threshold;
        Ok(())
    }



    pub fn request_join(
        ctx: Context<RequestJoin>,
        vehicle_id: String,
        trust_score: u8,
        _zkp_data: Vec<u8>,
    ) -> Result<()> {
        let platoon = &mut ctx.accounts.platoon;
        let vehicle = &ctx.accounts.vehicle;
    
        // 1. Check vehicle ID matches
        require!(
            vehicle.vehicle_id == vehicle_id,
            PlatoonError::Unauthorized
        );
        
    
    // 2. CRITICAL CHECK: Prevent malicious vehicles from joining
    // This is the most important check and should block any join attempt
    if vehicle.malicious_flag {
        msg!("❌ Vehicle {} is flagged as malicious and cannot join platoon", vehicle_id);
        return err!(PlatoonError::MaliciousVehicle);
    }
    
    // 3. Original access flag check can remain as a secondary protection
    require!(
        vehicle.access_flags.can_join_platoon,
        PlatoonError::JoinPermissionDenied
    );
    
        
        // 4. Check if vehicle is already in platoon
        let already_joined = platoon
            .members
            .iter()
            .any(|member| member.vehicle_id == vehicle_id);
    
        if !already_joined {
            // 5. For new vehicles joining, enforce the trust threshold
            require!(
                trust_score >= platoon.trust_threshold,
                PlatoonError::TrustTooLow
            );
            
            // 6. Check if platoon is full when adding a new member
            require!(
                platoon.members.len() < MAX_MEMBERS,
                PlatoonError::MaxMembersReached
            );
            
            // 7. Add the new vehicle to platoon
            platoon.members.push(MemberInfo{ vehicle_id: vehicle_id.clone(), trust_score });
            platoon.sum_trust += trust_score as u32;
            platoon.member_count += 1;
            
            msg!("✅ Added new vehicle {} to platoon with score {}", vehicle_id, trust_score);
        } else {
            // For existing vehicles, first check for suspicious trust score drop
            if let Some(index) = platoon
                .members
                .iter()
                .position(|member| member.vehicle_id == vehicle_id)
            {
                let old_trust = platoon.members[index].trust_score;
                msg!("🚨 old trust score is  {} and new one is {}", 
                old_trust , trust_score);
                // Check for suspicious trust score drop (more than 5 points)
                if old_trust > trust_score && old_trust - trust_score > 4 {
                    msg!("🚨 Suspicious trust score drop detected for {}: {} → {}", 
                        vehicle_id, old_trust, trust_score);
                    
                    // Flag the vehicle as malicious via CPI
                    let cpi_program = ctx.accounts.vehicle_program.to_account_info();
                    let cpi_accounts = vehicle_node_chain::cpi::accounts::VerifyZKP {
                        vehicle: vehicle.to_account_info(),
                        authority: ctx.accounts.rsu_signer.to_account_info(),
                    };
                    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
                    
                    // Use invalid hash to trigger malicious flag
                    let dummy_hash = [0u8; 32];
                    let _ = vehicle_node_chain::cpi::verify_zkp(cpi_ctx, trust_score, dummy_hash)?;
                    
                    // Update aggregates
                    platoon.sum_trust = platoon
                        .sum_trust
                        .saturating_sub(old_trust as u32);
                    platoon.member_count = platoon.member_count.saturating_sub(1);
                    
                    // Remove the member
                    platoon.members.remove(index);
                    
                    // Update vehicle status via CPI
                    let cpi_program = ctx.accounts.vehicle_program.to_account_info();
                    let cpi_accounts = JoinPlatoonAndShareData {
                        vehicle: vehicle.to_account_info(),
                        rsu_signer: ctx.accounts.rsu_signer.to_account_info(),
                    };
                    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
                    vehicle_node_chain::cpi::join_platoon_and_share_data(
                        cpi_ctx,
                        "removed_as_malicious".to_string(),
                    )?;
                    
                    // Reset status to not_joined
                    let cpi_program2 = ctx.accounts.vehicle_program.to_account_info();
                    let cpi_accounts2 = JoinPlatoonAndShareData {
                        vehicle: vehicle.to_account_info(),
                        rsu_signer: ctx.accounts.rsu_signer.to_account_info(),
                    };
                    let cpi_ctx2 = CpiContext::new(cpi_program2, cpi_accounts2);
                    vehicle_node_chain::cpi::join_platoon_and_share_data(
                        cpi_ctx2,
                        "not_joined".to_string(),
                    )?;
                    
                    return Ok(());
                }
                
                // 8. Then check if trust score falls below threshold
                if trust_score < platoon.trust_threshold {
                    // Score is below threshold - need to remove vehicle from platoon
                    msg!("⚠️ Trust score {} below threshold {} - removing vehicle from platoon", 
                        trust_score, platoon.trust_threshold);
                    
                    // Update aggregates
                    platoon.sum_trust = platoon
                        .sum_trust
                        .saturating_sub(old_trust as u32);
                    platoon.member_count = platoon.member_count.saturating_sub(1);
                    
                    // Remove the member
                    platoon.members.remove(index);
                    
                    // Update vehicle status via CPI to "removed_from_<rsu_id>"
                    let cpi_program = ctx.accounts.vehicle_program.to_account_info();
                    let cpi_accounts = JoinPlatoonAndShareData {
                        vehicle: vehicle.to_account_info(),
                        rsu_signer: ctx.accounts.rsu_signer.to_account_info(),
                    };
                    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
                    vehicle_node_chain::cpi::join_platoon_and_share_data(
                        cpi_ctx,
                        format!("removed_from_{}", platoon.rsu_id),
                    )?;
                    
                    // Reset status to not_joined
                    let cpi_program2 = ctx.accounts.vehicle_program.to_account_info();
                    let cpi_accounts2 = JoinPlatoonAndShareData {
                        vehicle: vehicle.to_account_info(),
                        rsu_signer: ctx.accounts.rsu_signer.to_account_info(),
                    };
                    let cpi_ctx2 = CpiContext::new(cpi_program2, cpi_accounts2);
                    vehicle_node_chain::cpi::join_platoon_and_share_data(
                        cpi_ctx2,
                        "not_joined".to_string(),
                    )?;
                    
                    return Ok(());
                } else {
                    // Trust score is still above threshold, update as normal
                    // Update to new score
                    platoon.members[index].trust_score = trust_score;
                    
                    // Update the sum_trust aggregate
                    platoon.sum_trust = platoon
                        .sum_trust
                        .saturating_sub(old_trust as u32)
                        .saturating_add(trust_score as u32);
                    
                    msg!("🔄 Updated trust score for {}: {} → {}", vehicle_id, old_trust, trust_score);
                }
            }
        }
    
        // 9. CPI to update/maintain vehicle status as "joined_<rsu_id>"
        // (Only reaches here for new joins or updates that maintain threshold)
        let cpi_program = ctx.accounts.vehicle_program.to_account_info();
        let cpi_accounts = JoinPlatoonAndShareData {
            vehicle: vehicle.to_account_info(),
            rsu_signer: ctx.accounts.rsu_signer.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        vehicle_node_chain::cpi::join_platoon_and_share_data(
            cpi_ctx,
            format!("joined_{}", platoon.rsu_id),
        )?;
    
        Ok(())
    }





    pub fn receive_global_rewards(ctx: Context<ReceiveRewards>, reward_amount: u64) -> Result<()> {
        let platoon = &mut ctx.accounts.platoon;
        let config = &ctx.accounts.config;
        
        // Check that the global server key matches the one in config
        require_keys_eq!(
            ctx.accounts.global_server.key(),
            config.global_server_pubkey,
            PlatoonError::Unauthorized
        );
        
        // Add rewards to the platoon
        platoon.total_rewards = platoon.total_rewards.checked_add(reward_amount)
            .ok_or(PlatoonError::ArithmeticError)?;
        
        Ok(())
    }

    pub fn distribute_rewards(ctx: Context<DistributeRewards>, amount: u64) -> Result<()> {
        let platoon = &mut ctx.accounts.platoon;
        
        // Ensure the RSU signer is the platoon creator
        require!(
            ctx.accounts.rsu_signer.key() == platoon.created_by,
            PlatoonError::Unauthorized
        );
        
        // Check that there are enough rewards to distribute
        require!(amount <= platoon.total_rewards, PlatoonError::NotEnoughRewards);
        
        // Reduce the total rewards by the distributed amount
        platoon.total_rewards = platoon.total_rewards.checked_sub(amount)
            .ok_or(PlatoonError::ArithmeticError)?;
        
        // In a real implementation, you would include logic here to 
        // distribute tokens to individual vehicles
        
        Ok(())
    }

    pub fn remove_vehicle(ctx: Context<RemoveVehicle>, vehicle_id: String) -> Result<()> {
        let platoon = &mut ctx.accounts.platoon;
    
        // RSU signer must be the creator
        require!(
            ctx.accounts.rsu_signer.key() == platoon.created_by,
            PlatoonError::Unauthorized
        );
    
        // find the member first
        if let Some(index) = platoon
            .members
            .iter()
            .position(|member| member.vehicle_id == vehicle_id)
        {
            // grab the old trust before removing
            let old_trust = platoon.members[index].trust_score;
    
            // update aggregates
            platoon.sum_trust = platoon
                .sum_trust
                .saturating_sub(old_trust as u32);
            platoon.member_count = platoon.member_count.saturating_sub(1);
    
            // now remove the entry
            platoon.members.remove(index);
            msg!("✅ Removed vehicle_id {} from platoon", vehicle_id);
        } else {
            msg!("🚫 Vehicle not found");
            return err!(PlatoonError::VehicleNotFound);
        }
    
        // --- CPI calls (unchanged) ---
        let cpi_program = ctx.accounts.vehicle_program.to_account_info();
        let cpi_accounts = JoinPlatoonAndShareData {
            vehicle: ctx.accounts.vehicle.to_account_info(),
            rsu_signer: ctx.accounts.rsu_signer.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        vehicle_node_chain::cpi::join_platoon_and_share_data(
            cpi_ctx,
            format!("removed_from_{}", platoon.rsu_id),
        )?;
    
        // reset status to not_joined
        let cpi_program2 = ctx.accounts.vehicle_program.to_account_info();
        let cpi_accounts2 = JoinPlatoonAndShareData {
            vehicle: ctx.accounts.vehicle.to_account_info(),
            rsu_signer: ctx.accounts.rsu_signer.to_account_info(),
        };
        let cpi_ctx2 = CpiContext::new(cpi_program2, cpi_accounts2);
        vehicle_node_chain::cpi::join_platoon_and_share_data(
            cpi_ctx2,
            "not_joined".to_string(),
        )?;
    
        Ok(())
    }
    

    pub fn close_platoon(ctx: Context<ClosePlatoon>) -> Result<()> {
        // Check that the creator is closing the platoon
        require!(
            ctx.accounts.creator.key() == ctx.accounts.platoon.created_by,
            PlatoonError::Unauthorized
        );
        
        // The account will be closed by Anchor after this instruction completes
        Ok(())
    }

    pub fn refresh_trust_score(ctx: Context<RefreshScore>, vehicle_id: String) -> Result<()> {
        let platoon = &mut ctx.accounts.platoon;
        let vehicle = &ctx.accounts.vehicle;
    
        // Ensure this is the right vehicle
        require!(vehicle.vehicle_id == vehicle_id, PlatoonError::Unauthorized);
    
        // Find vehicle in members list and update score
        let mut found = false;
        for member in &mut platoon.members {
            if member.vehicle_id == vehicle_id {
                let old = member.trust_score;
                member.trust_score = vehicle.trust_score;
                platoon.sum_trust = platoon
                    .sum_trust
                    .saturating_sub(old as u32)
                    .saturating_add(vehicle.trust_score as u32);
                msg!("🔁 Updated {} trust score: {} → {}", vehicle_id, old, vehicle.trust_score);
                found = true;
                break;
            }
        }
    
        if !found {
            msg!("⚠️ Vehicle not found in platoon.");
            return err!(PlatoonError::VehicleNotFound);
        }
    
        Ok(())
    }
    
}

#[account]
#[derive(Default)]
pub struct Platoon {
    pub rsu_id: String,
    pub trust_threshold: u8,
    pub created_by: Pubkey,
    pub members: Vec<MemberInfo>, // Using MemberInfo struct
    pub total_rewards: u64,

    pub sum_trust: u32,
    pub member_count: u16,
    pub last_pull_slot: u64,   // reward rate‑limit

}

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 32 // Discriminator + pubkey + admin pubkey
    )]
    pub config: Account<'info, PlatoonConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, PlatoonConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(rsu_id: String)]
pub struct InitializePlatoon<'info> {
    #[account(
        init,
        payer = creator,
        space = 8 + // Discriminator
               4 + MAX_RSU_ID_LENGTH + // rsu_id: String
               1 + // trust_threshold: u8
               32 + // created_by: Pubkey
               4 + (32 * MAX_MEMBERS) + // members: Vec<MemberInfo>
               8 + 4 + 8 + 4, // total_rewards: u64
        seeds = [b"platoon", rsu_id.as_bytes()],
        bump
    )]
    pub platoon: Account<'info, Platoon>,
    #[account(mut)]
    pub creator: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateThreshold<'info> {
    #[account(mut)]
    pub platoon: Account<'info, Platoon>,
    #[account(mut)]
    pub creator: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(vehicle_id: String)]
pub struct RequestJoin<'info> {
    #[account(mut)]
    pub platoon: Account<'info, Platoon>,
    #[account(mut, constraint = vehicle.vehicle_id == vehicle_id)]
    pub vehicle: Account<'info, vehicle_node_chain::VehicleNode>,
    pub vehicle_program: Program<'info, VehicleNodeChain>,
    #[account(signer)]
    /// CHECK: RSU signer should be the platoon creator
    pub rsu_signer: AccountInfo<'info>,
}


#[derive(Accounts)]
pub struct ReceiveRewards<'info> {
    #[account(mut)]
    pub platoon: Account<'info, Platoon>,
    pub config: Account<'info, PlatoonConfig>,
    #[account(signer)]
    /// CHECK: Matched against config.global_server_pubkey in instruction
    pub global_server: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DistributeRewards<'info> {
    #[account(mut)]
    pub platoon: Account<'info, Platoon>,
    #[account(signer)]
    /// CHECK: Verified against platoon creator in instruction
    pub rsu_signer: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct RemoveVehicle<'info> {
    #[account(mut)]
    pub platoon: Account<'info, Platoon>,
    #[account(mut)]
    pub vehicle: Account<'info, vehicle_node_chain::VehicleNode>,
    pub vehicle_program: Program<'info, VehicleNodeChain>,
    #[account(signer)]
    /// CHECK: This is the RSU signer, verified in the instruction by comparing with platoon.created_by
    pub rsu_signer: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ClosePlatoon<'info> {
    #[account(mut, close = creator)]
    pub platoon: Account<'info, Platoon>,
    #[account(mut)]
    pub creator: Signer<'info>,
}
#[derive(Accounts)]
#[instruction(vehicle_id: String)]  // Add this line to fix potential IDL issues
pub struct RefreshScore<'info> {
    #[account(mut)]
    pub platoon: Account<'info, Platoon>,

    #[account(
        seeds = [b"vehicle_node", vehicle.vehicle_id.as_bytes()],
        bump,
    )]
    pub vehicle: Account<'info, vehicle_node_chain::VehicleNode>,

    #[account(signer)]
    /// CHECK: RSU or admin who wants to refresh
    pub authority: AccountInfo<'info>,
}


#[error_code]
pub enum PlatoonError {
    #[msg("Vehicle already joined.")]
    AlreadyJoined,
    #[msg("Only the creator can update the threshold.")]
    Unauthorized,
    #[msg("Trust score below required threshold.")]
    TrustTooLow,
    #[msg("Vehicle not found in platoon.")]
    VehicleNotFound,
    #[msg("Invalid input parameters.")]
    InvalidInput,
    #[msg("Arithmetic error occurred.")]
    ArithmeticError,
    #[msg("Maximum number of members reached.")]
    MaxMembersReached,
    #[msg("Not enough rewards available.")]
    NotEnoughRewards,
    #[msg("Vehicle has been flagged as malicious and cannot join platoons.")]
    MaliciousVehicle,
    #[msg("Vehicle doesn't have permission to join platoons.")]
    JoinPermissionDenied,
}
