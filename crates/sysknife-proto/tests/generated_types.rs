use sysknife_proto::sysknife::v1::{
    FailureCategory, JobState, PreviewEnvelope, RequestEnvelope, ResultEnvelope, TransactionRecord,
};

#[test]
fn generated_types_compile() {
    let _ = RequestEnvelope::default();
    let _ = PreviewEnvelope::default();
    let _ = ResultEnvelope::default();
    let _ = TransactionRecord::default();
    let _ = FailureCategory::default();
    let _ = JobState::default();
}
