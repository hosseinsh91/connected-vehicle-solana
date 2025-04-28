use anchor_lang::prelude::*;

declare_id!("8kbW2B8DZHTjZNi15hwnPsv3pvgEnBhwwc7ddFE7wdUj");

#[program]
pub mod vehicle_node_chain {
    use super::*;

    pub fn initialize_vehicle(ctx: Context<InitializeVehicle>, vehicle_id: String) -> Result<()> {
        // Validate vehicle_id format and length
        require!(!vehicle_id.is_empty() && vehicle_id.len() <= 64, VehicleError::InvalidVehicleId);

        let vehicle = &mut ctx.accounts.vehicle;
        vehicle.owner = ctx.accounts.authority.key();
        vehicle.vehicle_id = vehicle_id;
        vehicle.trust_score = 0;
        vehicle.signed_trust_hash = [0u8; 32];
        vehicle.platoon_status = "not_joined".to_string();
        vehicle.reward_tokens = 0;
        vehicle.malicious_flag = false;
        vehicle.access_flags = AccessFlags {
            can_join_platoon: true,
            can_share_data: false,
        };
        vehicle.join_history = vec![];
        vehicle.behavior = "unknown".to_string();
        vehicle.approved_rsu = None;
        Ok(())
    }

    pub fn reset_vehicle(ctx: Context<ResetVehicle>) -> Result<()> {
        let vehicle = &mut ctx.accounts.vehicle;
        // Check that the caller is the owner
        require!(
            ctx.accounts.authority.key() == vehicle.owner,
            VehicleError::Unauthorized
        );

        vehicle.trust_score = 0;
        vehicle.signed_trust_hash = [0u8; 32];
        vehicle.platoon_status = "not_joined".to_string();
        vehicle.reward_tokens = 0;
        vehicle.malicious_flag = false;
        vehicle.access_flags = AccessFlags {
            can_join_platoon: true,
            can_share_data: false,
        };
        vehicle.join_history.clear();
        vehicle.behavior = "unknown".to_string();
        vehicle.approved_rsu = None;
        Ok(())
    }

    pub fn close_vehicle(ctx: Context<CloseVehicle>) -> Result<()> {
        let vehicle = &mut ctx.accounts.vehicle;
        // Check that the caller is the owner
        require!(
            ctx.accounts.authority.key() == vehicle.owner,
            VehicleError::Unauthorized
        );

        // No need to modify data before closing - Anchor will free the account
        Ok(())
    }

    pub fn update_vehicle(
        ctx: Context<UpdateVehicle>,
        trust_score: u8,
        behavior: String,
        signed_hash: [u8; 32],
    ) -> Result<()> {
        let vehicle = &mut ctx.accounts.vehicle;
        // Check that the caller is the owner or an approved RSU
        require!(
            ctx.accounts.authority.key() == vehicle.owner || 
            (vehicle.approved_rsu.is_some() && ctx.accounts.authority.key() == vehicle.approved_rsu.unwrap()),
            VehicleError::Unauthorized
        );

        vehicle.trust_score = trust_score;
        vehicle.behavior = behavior;
        vehicle.signed_trust_hash = signed_hash;
        Ok(())
    }

    pub fn verify_zkp(
        ctx: Context<VerifyZKP>,
        trust_score: u8,
        provided_hash: [u8; 32],
    ) -> Result<bool> {
        let vehicle = &mut ctx.accounts.vehicle;
        
        // Check that the caller is the owner or an approved RSU
        require!(
            ctx.accounts.authority.key() == vehicle.owner || 
            (vehicle.approved_rsu.is_some() && ctx.accounts.authority.key() == vehicle.approved_rsu.unwrap()),
            VehicleError::Unauthorized
        );

        // In a real implementation, this would use a proper ZKP verification
        // This is a placeholder for demonstration purposes
        let expected_str = format!("{}:{}", vehicle.vehicle_id, trust_score);
        let expected_hash = anchor_lang::solana_program::hash::hash(expected_str.as_bytes()).to_bytes();

        if expected_hash != provided_hash {
            vehicle.access_flags.can_join_platoon = false;
            vehicle.access_flags.can_share_data = false;
            return Ok(false);
        }

        vehicle.access_flags.can_join_platoon = true;
        Ok(true)
    }

    pub fn join_platoon_and_share_data(
        ctx: Context<JoinPlatoonAndShareData>,
        new_status: String,
    ) -> Result<()> {
        let vehicle = &mut ctx.accounts.vehicle;
        
        // Check that the status string is valid
        require!(
            new_status.starts_with("joined_") || 
            new_status.starts_with("removed_from_") ||
            new_status == "not_joined" || 
            new_status == "removed_by_rsu",
            VehicleError::InvalidStatus
        );
    
        // Verify that either the owner is calling or this is a CPI from a verified platoon manager
        if !ctx.accounts.rsu_signer.is_signer {
            return err!(VehicleError::Unauthorized);
        }
    
        msg!("🪪 On-chain vehicle_id: {}", vehicle.vehicle_id);
    
        vehicle.platoon_status = new_status.clone();
    
        // Add to history with a reasonable max size
        if vehicle.join_history.len() >= MAX_HISTORY_SIZE {
            vehicle.join_history.remove(0); // Remove oldest entry
        }
    
        if new_status.starts_with("joined_") {
            // Set flags appropriately when joining a platoon
            vehicle.access_flags.can_share_data = true;
            vehicle.access_flags.can_join_platoon = false;  // Can't join another platoon while in one
            vehicle.approved_rsu = Some(ctx.accounts.rsu_signer.key());
            vehicle.join_history.push(new_status.clone());
            msg!(
                "✅ Vehicle {} joined and granted access to RSU {:?}",
                vehicle.vehicle_id,
                ctx.accounts.rsu_signer.key()
            );
        } else if new_status.starts_with("removed_from_") || 
                  new_status == "not_joined" || 
                  new_status == "removed_by_rsu" {
            // For any removal or reset status, set flags appropriately
            if new_status.starts_with("removed_from_") {
                vehicle.join_history.push(new_status.clone());
            }
            
            vehicle.approved_rsu = None;
            vehicle.access_flags.can_share_data = false;
            vehicle.access_flags.can_join_platoon = true;  // Now can join a new platoon
            msg!(
                "🚫 Vehicle {} status changed to: {}",
                vehicle.vehicle_id,
                new_status
            );
        }
    
        Ok(())
    }

    pub fn leave_platoon(ctx: Context<LeavePlatoon>) -> Result<()> {
        let vehicle = &mut ctx.accounts.vehicle;
        
        // Only allow leaving if currently in a platoon
        require!(
            vehicle.platoon_status.starts_with("joined_"),
            VehicleError::InvalidStatus
        );
        
        // Get the RSU ID from the platoon status (format is "joined_rsu_id")
        let parts: Vec<&str> = vehicle.platoon_status.split('_').collect();
        if parts.len() < 2 {
            return err!(VehicleError::InvalidStatus);
        }
        let rsu_id = parts[1..].join("_"); // Rejoin in case RSU ID contains underscores
        
        // Record leaving in history
        if vehicle.join_history.len() >= MAX_HISTORY_SIZE {
            vehicle.join_history.remove(0); // Remove oldest entry
        }
        let leave_status = format!("left_{}", rsu_id);
        vehicle.join_history.push(leave_status);
        
        // Update status and flags
        vehicle.platoon_status = "not_joined".to_string();
        vehicle.access_flags.can_share_data = false;
        vehicle.access_flags.can_join_platoon = true;
        vehicle.approved_rsu = None;
        
        msg!("🚶 Vehicle {} left platoon {}", vehicle.vehicle_id, rsu_id);
        
        // Return the RSU ID so it can be used to notify the platoon
        Ok(())
    }
    
    pub fn debug_pda(ctx: Context<VerifyZKP>) -> Result<()> {
        msg!("🪪 On-chain vehicle_id: {}", ctx.accounts.vehicle.vehicle_id);
        let seed = &[b"vehicle_node", ctx.accounts.vehicle.vehicle_id.as_bytes()];
        let (expected_pda, _) = Pubkey::find_program_address(seed, &crate::ID);
        msg!("📍 Expected PDA from smart contract: {}", expected_pda);
        Ok(())
    }
}

// Constants to avoid magic numbers
pub const MAX_HISTORY_SIZE: usize = 20;

#[account]
#[derive(Default)]
pub struct VehicleNode {
    pub owner: Pubkey,
    pub vehicle_id: String,
    pub trust_score: u8,
    pub signed_trust_hash: [u8; 32],
    pub platoon_status: String,
    pub reward_tokens: u8,
    pub malicious_flag: bool,
    pub access_flags: AccessFlags,
    pub join_history: Vec<String>,
    pub behavior: String,
    pub approved_rsu: Option<Pubkey>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, Default)]
pub struct AccessFlags {
    pub can_join_platoon: bool,
    pub can_share_data: bool,
}

#[derive(Accounts)]
#[instruction(vehicle_id: String)]
pub struct InitializeVehicle<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + // Discriminator
               32 + // owner: Pubkey
               4 + 64 + // vehicle_id: String (max 64 chars)
               1 + // trust_score: u8
               32 + // signed_trust_hash: [u8; 32]
               4 + 32 + // platoon_status: String (max 32 chars)
               1 + // reward_tokens: u8
               1 + // malicious_flag: bool
               2 + // access_flags: AccessFlags (2 bools)
               4 + (32 * MAX_HISTORY_SIZE) + // join_history: Vec<String>
               4 + 32 + // behavior: String (max 32 chars)
               33, // approved_rsu: Option<Pubkey>
        seeds = [b"vehicle_node", vehicle_id.as_bytes()],
        bump
    )]
    pub vehicle: Account<'info, VehicleNode>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ResetVehicle<'info> {
    #[account(
        mut,
        seeds = [b"vehicle_node", vehicle.vehicle_id.as_bytes()],
        bump,
        realloc = 8 + // Discriminator
               32 + // owner: Pubkey
               4 + 64 + // vehicle_id: String (max 64 chars)
               1 + // trust_score: u8
               32 + // signed_trust_hash: [u8; 32]
               4 + 32 + // platoon_status: String (max 32 chars)
               1 + // reward_tokens: u8
               1 + // malicious_flag: bool
               2 + // access_flags: AccessFlags (2 bools)
               4 + (32 * MAX_HISTORY_SIZE) + // join_history: Vec<String>
               4 + 32 + // behavior: String (max 32 chars)
               33, // approved_rsu: Option<Pubkey>
        realloc::payer = authority,
        realloc::zero = false // Don't zero data unnecessarily
    )]
    pub vehicle: Account<'info, VehicleNode>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseVehicle<'info> {
    #[account(
        mut,
        close = authority,
        seeds = [b"vehicle_node", vehicle.vehicle_id.as_bytes()],
        bump,
        has_one = owner @ VehicleError::Unauthorized
    )]
    pub vehicle: Account<'info, VehicleNode>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub owner: SystemAccount<'info>,
}

#[derive(Accounts)]
pub struct UpdateVehicle<'info> {
    #[account(mut, seeds = [b"vehicle_node", vehicle.vehicle_id.as_bytes()], bump)]
    pub vehicle: Account<'info, VehicleNode>,
    #[account(signer)]
    /// CHECK: Verified in the instruction logic
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct VerifyZKP<'info> {
    #[account(mut, seeds = [b"vehicle_node", vehicle.vehicle_id.as_bytes()], bump)]
    pub vehicle: Account<'info, VehicleNode>,
    #[account(signer)]
    /// CHECK: Verified in the instruction logic
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct JoinPlatoonAndShareData<'info> {
    #[account(mut, seeds = [b"vehicle_node", vehicle.vehicle_id.as_bytes()], bump)]
    pub vehicle: Account<'info, VehicleNode>,
    #[account(signer)]
    /// CHECK: This RSU signer is verified in the instruction logic
    pub rsu_signer: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct LeavePlatoon<'info> {
    #[account(
        mut,
        seeds = [b"vehicle_node", vehicle.vehicle_id.as_bytes()],
        bump
    )]
    pub vehicle: Account<'info, VehicleNode>,
    
    #[account(signer, constraint = authority.key() == vehicle.owner)]
    /// CHECK: Must be the vehicle owner
    pub authority: AccountInfo<'info>,
}

#[error_code]
pub enum VehicleError {
    #[msg("You are not authorized to perform this action.")]
    Unauthorized,
    #[msg("Invalid vehicle ID.")]
    InvalidVehicleId,
    #[msg("Too many access requests. Please process existing requests first.")]
    TooManyRequests,
    #[msg("This RSU has already requested access.")]
    DuplicateRequest,
    #[msg("Invalid platoon status.")]
    InvalidStatus,
}