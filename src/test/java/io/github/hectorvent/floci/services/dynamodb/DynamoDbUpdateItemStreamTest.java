package io.github.hectorvent.floci.services.dynamodb;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.services.dynamodb.model.AttributeDefinition;
import io.github.hectorvent.floci.services.dynamodb.model.DynamoDbStreamRecord;
import io.github.hectorvent.floci.services.dynamodb.model.KeySchemaElement;
import io.github.hectorvent.floci.services.dynamodb.model.TableDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * DynamoDB Streams records an UpdateItem that creates a missing key as INSERT, with no OldImage.
 * MODIFY is a change to an item that already exists.
 */
class DynamoDbUpdateItemStreamTest {

    private static final String REGION = "us-east-1";
    private static final String TABLE = "Items";

    private final ObjectMapper mapper = new ObjectMapper();
    private DynamoDbService service;
    private DynamoDbStreamService streamService;
    private KinesisStreamingForwarder kinesisForwarder;
    private TableDefinition table;

    @BeforeEach
    void setUp() {
        StorageBackend<String, TableDefinition> tableStore = new InMemoryStorage<>();
        streamService = new DynamoDbStreamService(mapper, tableStore);
        kinesisForwarder = mock(KinesisStreamingForwarder.class);
        service = new DynamoDbService(
                tableStore,
                new InMemoryStorage<>(),
                new RegionResolver(REGION, "000000000000"),
                streamService,
                kinesisForwarder);
        service.createTable(TABLE,
                List.of(new KeySchemaElement("pk", "HASH")),
                List.of(new AttributeDefinition("pk", "S")),
                5L, 5L, REGION);
        table = service.enableStream(TABLE, "NEW_AND_OLD_IMAGES", REGION);
    }

    @Test
    void updateItemThatCreatesAKeyEmitsInsertWithoutOldImage() {
        update("created", "hello");

        List<DynamoDbStreamRecord> records = records();
        assertEquals(1, records.size());
        assertEquals("INSERT", records.get(0).getEventName());
        assertNull(records.get(0).getOldImage());
        assertEquals("hello", records.get(0).getNewImage().get("note").get("S").asText());

        ArgumentCaptor<JsonNode> oldImage = ArgumentCaptor.forClass(JsonNode.class);
        verify(kinesisForwarder).forward(eq("INSERT"), oldImage.capture(), any(), any(), eq(REGION), any());
        assertNull(oldImage.getValue());
    }

    @Test
    void updateItemThatChangesAnExistingKeyEmitsModify() {
        update("created", "hello");
        update("created", "world");

        List<DynamoDbStreamRecord> records = records();
        assertEquals(2, records.size());
        assertEquals("MODIFY", records.get(1).getEventName());
        assertEquals("hello", records.get(1).getOldImage().get("note").get("S").asText());
        assertEquals("world", records.get(1).getNewImage().get("note").get("S").asText());

        ArgumentCaptor<String> eventNames = ArgumentCaptor.forClass(String.class);
        verify(kinesisForwarder, times(2)).forward(eventNames.capture(), any(), any(), any(), eq(REGION), any());
        assertEquals(List.of("INSERT", "MODIFY"), eventNames.getAllValues());
    }

    private void update(String key, String data) {
        ObjectNode itemKey = mapper.createObjectNode();
        itemKey.set("pk", stringAttr(key));
        ObjectNode values = mapper.createObjectNode();
        values.set(":v", stringAttr(data));
        service.updateItem(TABLE, itemKey, null, "SET note = :v", null, values, "NONE", REGION);
    }

    private ObjectNode stringAttr(String value) {
        ObjectNode node = mapper.createObjectNode();
        node.put("S", value);
        return node;
    }

    private List<DynamoDbStreamRecord> records() {
        String iterator = streamService.getShardIterator(table.getStreamArn(),
                DynamoDbStreamService.SHARD_ID, "TRIM_HORIZON", null);
        return streamService.getRecords(iterator, 10).records();
    }
}
