use num_enum::TryFromPrimitive;

/// The priority_flag parameter allows the originating SME to assign a priority level to the short
/// message. Level 0 is the lowest priority, level 3 the highest

#[derive(TryFromPrimitive)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PriorityFlag {
    /// GSM: non-priority, ANSI-136: Bulk, IS-95: Normal
    Level0 = 0,

    /// GSM: priority, ANSI-136: Normal, IS-95: Interactive
    Level1 = 1,

    /// GSM: priority, ANSI-136: Urgent, IS-95: Urgent
    Level2 = 2,

    /// GSM: priority, ANSI-136: VeryUrgent, IS-95: Emergency
    Level3 = 3,
    // levels > 3 are reserved
}
