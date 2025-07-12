// ABOUTME: Comprehensive benchmark suite for SMPP library performance testing
// ABOUTME: Measures frame parsing, serialization, and memory allocation patterns

use bytes::BytesMut;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use smpp::datatypes::*;
use smpp::frame::Frame;
use std::io::Cursor;
use std::time::Duration;

fn create_sample_submit_sm() -> SubmitSm {
    SubmitSm {
        command_status: CommandStatus::Ok,
        sequence_number: 1,
        service_type: ServiceType::from(""),
        source_addr_ton: TypeOfNumber::Unknown,
        source_addr_npi: NumericPlanIndicator::Unknown,
        source_addr: SourceAddr::from("12345"),
        dest_addr_ton: TypeOfNumber::Unknown,
        dest_addr_npi: NumericPlanIndicator::Unknown,
        destination_addr: DestinationAddr::from("67890"),
        esm_class: 0,
        protocol_id: 0,
        priority_flag: PriorityFlag::Level0,
        schedule_delivery_time: ScheduleDeliveryTime::from(""),
        validity_period: ValidityPeriod::from(""),
        registered_delivery: 0,
        replace_if_present_flag: 0,
        data_coding: 0,
        sm_default_msg_id: 0,
        sm_length: 11,
        short_message: ShortMessage::from("Hello World"),
        user_message_reference: None,
        source_port: None,
        source_addr_submit: None,
        destination_port: None,
        dest_addr_submit: None,
        sar_msg_ref_num: None,
        sar_total_segments: None,
        sar_segment_seqnum: None,
        more_messages_to_send: None,
        payload_type: None,
        message_payload: None,
        privacy_indicator: None,
        callback_num: None,
        callback_num_pres_ind: None,
        callback_num_atag: None,
        source_subaddress: None,
        dest_subaddress: None,
        display_time: None,
        sms_signal: None,
        ms_validity: None,
        ms_msg_wait_facilities: None,
        number_of_messages: None,
        alert_on_msg_delivery: None,
        language_indicator: None,
        its_reply_type: None,
        its_session_info: None,
        ussd_service_op: None,
    }
}

fn create_sample_bind_transmitter() -> BindTransmitter {
    BindTransmitter {
        command_status: CommandStatus::Ok,
        sequence_number: 1,
        system_id: SystemId::from("test_system"),
        password: Some(Password::from("password")),
        system_type: SystemType::from(""),
        interface_version: InterfaceVersion::SmppV34,
        addr_ton: TypeOfNumber::Unknown,
        addr_npi: NumericPlanIndicator::Unknown,
        address_range: AddressRange::from(""),
    }
}

fn create_sample_enquire_link() -> EnquireLink {
    EnquireLink { sequence_number: 1 }
}

fn create_sample_deliver_sm() -> DeliverSm {
    DeliverSm {
        command_status: CommandStatus::Ok,
        sequence_number: 1,
        service_type: ServiceType::from(""),
        source_addr_ton: TypeOfNumber::Unknown,
        source_addr_npi: NumericPlanIndicator::Unknown,
        source_addr: SourceAddr::from("12345"),
        dest_addr_ton: TypeOfNumber::Unknown,
        dest_addr_npi: NumericPlanIndicator::Unknown,
        destination_addr: DestinationAddr::from("67890"),
        esm_class: 0,
        protocol_id: 0,
        priority_flag: 0,
        schedule_delivery_time: ScheduleDeliveryTime::from(""),
        validity_period: ValidityPeriod::from(""),
        registered_delivery: 0,
        replace_if_present_flag: 0,
        data_coding: 0,
        sm_default_msg_id: 0,
        sm_length: 11,
        short_message: ShortMessage::from("Hello World"),
        user_message_reference: None,
        source_port: None,
        destination_port: None,
        sar_msg_ref_num: None,
        sar_total_segments: None,
        sar_segment_seqnum: None,
        user_data_header: None,
        privacy_indicator: None,
        callback_num: None,
        source_subaddress: None,
        dest_subaddress: None,
        language_indicator: None,
        its_session_info: None,
        network_error_code: None,
        message_payload: None,
        delivery_failure_reason: None,
        additional_status_info_text: None,
        dpf_result: None,
        set_dpf: None,
        ms_availability_status: None,
        receipted_message_id: None,
        message_state: None,
    }
}

fn create_frame_bytes(pdu: impl ToBytes) -> Vec<u8> {
    // ToBytes already creates complete SMPP frames with headers
    pdu.to_bytes().to_vec()
}

fn bench_frame_check(c: &mut Criterion) {
    let submit_sm = create_sample_submit_sm();
    let frame_bytes = create_frame_bytes(submit_sm);

    let mut group = c.benchmark_group("frame_check");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("submit_sm", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(frame_bytes.as_slice()));
            Frame::check(&mut cursor)
        })
    });

    let enquire_link = create_sample_enquire_link();
    let enquire_frame_bytes = create_frame_bytes(enquire_link);

    group.bench_function("enquire_link", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(enquire_frame_bytes.as_slice()));
            Frame::check(&mut cursor)
        })
    });

    group.finish();
}

fn bench_frame_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_parse");
    group.measurement_time(Duration::from_secs(10));

    // SubmitSm parsing (complex PDU with TLVs)
    let submit_sm = create_sample_submit_sm();
    let submit_frame_bytes = create_frame_bytes(submit_sm);

    group.bench_function("submit_sm", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(submit_frame_bytes.as_slice()));
            Frame::parse(&mut cursor).unwrap()
        })
    });

    // DeliverSm parsing (complex PDU with TLVs)
    let deliver_sm = create_sample_deliver_sm();
    let deliver_frame_bytes = create_frame_bytes(deliver_sm);

    group.bench_function("deliver_sm", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(deliver_frame_bytes.as_slice()));
            Frame::parse(&mut cursor).unwrap()
        })
    });

    // BindTransmitter parsing (medium complexity)
    let bind_tx = create_sample_bind_transmitter();
    let bind_frame_bytes = create_frame_bytes(bind_tx);

    group.bench_function("bind_transmitter", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(bind_frame_bytes.as_slice()));
            Frame::parse(&mut cursor).unwrap()
        })
    });

    // EnquireLink parsing (simple PDU)
    let enquire_link = create_sample_enquire_link();
    let enquire_frame_bytes = create_frame_bytes(enquire_link);

    group.bench_function("enquire_link", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(enquire_frame_bytes.as_slice()));
            Frame::parse(&mut cursor).unwrap()
        })
    });

    group.finish();
}

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");
    group.measurement_time(Duration::from_secs(10));

    let submit_sm = create_sample_submit_sm();
    group.bench_function("submit_sm", |b| b.iter(|| black_box(&submit_sm).to_bytes()));

    let deliver_sm = create_sample_deliver_sm();
    group.bench_function("deliver_sm", |b| {
        b.iter(|| black_box(&deliver_sm).to_bytes())
    });

    let bind_tx = create_sample_bind_transmitter();
    group.bench_function("bind_transmitter", |b| {
        b.iter(|| black_box(&bind_tx).to_bytes())
    });

    let enquire_link = create_sample_enquire_link();
    group.bench_function("enquire_link", |b| {
        b.iter(|| black_box(&enquire_link).to_bytes())
    });

    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("submit_sm", |b| {
        b.iter(|| {
            let submit_sm = create_sample_submit_sm();
            let frame_bytes = create_frame_bytes(black_box(submit_sm));
            let mut cursor = Cursor::new(black_box(frame_bytes.as_slice()));
            Frame::parse(&mut cursor).unwrap()
        })
    });

    group.bench_function("enquire_link", |b| {
        b.iter(|| {
            let enquire_link = create_sample_enquire_link();
            let frame_bytes = create_frame_bytes(black_box(enquire_link));
            let mut cursor = Cursor::new(black_box(frame_bytes.as_slice()));
            Frame::parse(&mut cursor).unwrap()
        })
    });

    group.finish();
}

fn bench_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_sizes");
    group.measurement_time(Duration::from_secs(10));

    let message_sizes = [10, 50, 100, 160, 254]; // Common SMS message sizes

    for &size in &message_sizes {
        let message = "A".repeat(size);
        let mut submit_sm = create_sample_submit_sm();
        submit_sm.short_message = ShortMessage::from(message.as_str());
        submit_sm.sm_length = size as u8;

        let frame_bytes = create_frame_bytes(submit_sm);

        group.bench_with_input(
            BenchmarkId::new("submit_sm_parse", size),
            &frame_bytes,
            |b, frame_bytes| {
                b.iter(|| {
                    let mut cursor = Cursor::new(black_box(frame_bytes.as_slice()));
                    Frame::parse(&mut cursor).unwrap()
                })
            },
        );
    }

    group.finish();
}

fn bench_memory_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_allocation");
    group.measurement_time(Duration::from_secs(10));

    // Measure allocation patterns for different operations
    group.bench_function("bytesmut_allocation", |b| {
        b.iter(|| {
            let mut buf = BytesMut::new();
            buf.extend_from_slice(black_box(b"Hello World"));
            buf
        })
    });

    group.bench_function("string_allocation", |b| {
        b.iter(|| black_box("test_system".to_string()))
    });

    group.bench_function("vec_allocation", |b| {
        b.iter(|| black_box("Hello World".as_bytes().to_vec()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_frame_check,
    bench_frame_parse,
    bench_serialization,
    bench_roundtrip,
    bench_message_sizes,
    bench_memory_allocation
);
criterion_main!(benches);
