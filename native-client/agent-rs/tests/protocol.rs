#![allow(clippy::unwrap_used)]

use idengrid_agent::dto::{ConnectResponse, StoreDto, TicketResponse};

#[test]
fn protocol_fixtures_are_valid_json_and_match_runtime_dtos() {
    let store = include_str!("../protocol/fixtures/stores-response.json");
    let connect = include_str!("../protocol/fixtures/connect-response.json");
    let ticket = include_str!("../protocol/fixtures/ticket-response.json");
    let stores: Vec<StoreDto> = serde_json::from_str(store).unwrap();
    assert_eq!(stores.len(), 1);
    stores[0].validate().unwrap();
    serde_json::from_str::<ConnectResponse>(connect)
        .unwrap()
        .validate()
        .unwrap();
    serde_json::from_str::<TicketResponse>(ticket)
        .unwrap()
        .validate()
        .unwrap();

    for schema in [
        include_str!("../protocol/schema/agent-config.schema.json"),
        include_str!("../protocol/schema/control-request.schema.json"),
        include_str!("../protocol/schema/central-api.schema.json"),
    ] {
        let parsed: serde_json::Value = serde_json::from_str(schema).unwrap();
        assert_eq!(
            parsed["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
    }
}
