#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/md.h"
#include "nvs_flash.h"
#include <ArduinoJson.h>
#include <string>

#include "esp_websocket_client.h"
#include "mpack.h" // certifique-se de adicionar mpack no seu projeto

static const char *TAG = "B2WS";

#define WIFI_SSID "AGST UBI"
#define WIFI_PASS "AABBCCAABB"

static esp_websocket_client_handle_t client;

extern "C" {
void app_main(void);
}

void serializeJsonToMpack(mpack_writer_t *writer, JsonVariant variant) {
    if (variant.is<JsonObject>()) {
        JsonObject obj = variant.as<JsonObject>();
        mpack_start_map(writer, obj.size());
        for (JsonPair kv : obj) {
            mpack_write_cstr(writer, kv.key().c_str());
            serializeJsonToMpack(writer, kv.value());
        }
        mpack_finish_map(writer);
    }
    else if (variant.is<JsonArray>()) {
        JsonArray arr = variant.as<JsonArray>();
        mpack_start_array(writer, arr.size());
        for (JsonVariant v : arr) {
            serializeJsonToMpack(writer, v);
        }
        mpack_finish_array(writer);
    }
    else if (variant.is<const char *>()) {
        mpack_write_cstr(writer, variant.as<const char *>());
    }
    else if (variant.is<bool>()) {
        mpack_write_bool(writer, variant.as<bool>());
    }
    else if (variant.is<int>()) {
        mpack_write_int(writer, variant.as<int>());
    }
    else if (variant.is<long>()) {
        mpack_write_i64(writer, variant.as<long>());
    }
    else if (variant.is<float>() || variant.is<double>()) {
        mpack_write_double(writer, variant.as<double>());
    }
    else if (variant.isNull()) {
        mpack_write_nil(writer);
    }
    else {
        // fallback: serialize as string
        mpack_write_cstr(writer, variant.as<const char *>());
    }
}

void deserializeMpackToJsonInternal(mpack_node_t node, JsonVariant variant) {
    switch (mpack_node_type(node)) {
    case mpack_type_nil:
        variant.set(nullptr);
        break;
    case mpack_type_bool:
        variant.set(mpack_node_bool(node));
        break;
    case mpack_type_int:
        variant.set(mpack_node_i64(node));
        break;
    case mpack_type_uint:
        variant.set(mpack_node_u64(node));
        break;
    case mpack_type_float:
        variant.set(mpack_node_float(node));
        break;
    case mpack_type_double:
        variant.set(mpack_node_double(node));
        break;
    case mpack_type_str: {
        size_t len = mpack_node_strlen(node) + 1;

        char *strBuf = new char[len]();
        mpack_node_copy_cstr(node, strBuf, len);

        variant.set(strBuf);
        delete[] strBuf;
        break;
    }
    case mpack_type_array: {
        JsonArray arr = variant.to<JsonArray>();
        size_t count = mpack_node_array_length(node);
        for (size_t i = 0; i < count; ++i) {
            JsonVariant element = arr.add<JsonVariant>();
            deserializeMpackToJsonInternal(mpack_node_array_at(node, i), element);
        }
        break;
    }
    case mpack_type_map: {
        JsonObject obj = variant.to<JsonObject>();
        size_t count = mpack_node_map_count(node);
        for (size_t i = 0; i < count; ++i) {
            mpack_node_t keyNode = mpack_node_map_key_at(node, i);
            mpack_node_t valNode = mpack_node_map_value_at(node, i);

            size_t kLen = mpack_node_strlen(keyNode) + 1;

            char *keyBuf = new char[kLen]();
            mpack_node_copy_cstr(keyNode, keyBuf, kLen);

            obj[keyBuf].to<JsonVariant>();
            JsonVariant child = obj[keyBuf];
            delete[] keyBuf;
            deserializeMpackToJsonInternal(valNode, child);
        }
        break;
    }
    default:
        // Unsupported or unknown type.
        break;
    }
}

JsonDocument deserializeMpackToJson(mpack_node_t root) {
    JsonDocument doc;

    JsonVariant variant = doc.to<JsonVariant>();

    deserializeMpackToJsonInternal(root, variant);

    return doc; // Returna o JsonDocument.
}

void sendWebSockMessage(JsonDocument doc) {
    uint16_t strSize = measureJson(doc); // Pega o tamanho do JSON em string para garantir que vai caber no buffer do MessagePack
    // uint8_t msgpackBuf[256] __attribute__((aligned(4)));
    uint8_t *msgpackBuf = new uint8_t[strSize];
    mpack_writer_t writer;
    mpack_writer_init(&writer, (char *)msgpackBuf, strSize);

    serializeJsonToMpack(&writer, doc.as<JsonVariant>());

    size_t used = mpack_writer_buffer_used(&writer);

    if (!mpack_writer_destroy(&writer)) {
        int err = esp_websocket_client_send_bin(client, (const char *)msgpackBuf, used, portMAX_DELAY);
        if (err > 0) {
            ESP_LOGI(TAG, "Sent MessagePack response");
        }
        else {
            ESP_LOGE(TAG, "Failed to send WebSocket message");
        }
    }
    else {
        ESP_LOGE(TAG, "Failed to serialize MessagePack");
        mpack_error_t err = mpack_writer_error(&writer);
        ESP_LOGE(TAG, "MPack writer error: %d", err);
    }

    delete[] msgpackBuf;
}

/**
 * @brief Calcula a contrachave (resposta HMAC-SHA256).
 * * @param desafio A string de desafio recebida do servidor.
 * @param segredo O segredo compartilhado do dispositivo.
 * @param saida_buffer O buffer onde a resposta hexadecimal será escrita.
 * @param saida_buffer_len O tamanho do buffer de saída.
 * @return esp_err_t ESP_OK em sucesso, ESP_FAIL em erro.
 */
esp_err_t calculate_key(const char *desafio, const char *segredo, char *saida_buffer, size_t saida_buffer_len) {

    // O hash SHA-256 tem 32 bytes de saída binária.
    // Em hexadecimal, são 64 caracteres + 1 para o terminador nulo.
    if (saida_buffer_len < 65) {
        ESP_LOGE(TAG, "Buffer de saída muito pequeno!");
        return ESP_FAIL;
    }

    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md_info;
    unsigned char hmac_resultado[32]; // Saída binária do SHA-256

    // 1. Inicializa o contexto mbed TLS
    mbedtls_md_init(&ctx);
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (md_info == NULL) {
        ESP_LOGE(TAG, "Falha ao obter informações do mbedtls_md_info_from_type");
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }

    // 2. Configura o contexto para o modo HMAC com o segredo
    if (mbedtls_md_setup(&ctx, md_info, 1) != 0) { // 1 = hmac mode
        ESP_LOGE(TAG, "Falha no mbedtls_md_setup");
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }

    if (mbedtls_md_hmac_starts(&ctx, (const unsigned char *)segredo, strlen(segredo)) != 0) {
        ESP_LOGE(TAG, "Falha no mbedtls_md_hmac_starts");
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }

    // 3. Alimenta o desafio no cálculo do HMAC
    if (mbedtls_md_hmac_update(&ctx, (const unsigned char *)desafio, strlen(desafio)) != 0) {
        ESP_LOGE(TAG, "Falha no mbedtls_md_hmac_update");
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }

    // 4. Finaliza o cálculo e obtém o resultado binário
    if (mbedtls_md_hmac_finish(&ctx, hmac_resultado) != 0) {
        ESP_LOGE(TAG, "Falha no mbedtls_md_hmac_finish");
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }

    // Libera o contexto
    mbedtls_md_free(&ctx);

    // 5. Converte o resultado binário para uma string hexadecimal
    for (int i = 0; i < sizeof(hmac_resultado); i++) {
        sprintf(saida_buffer + (i * 2), "%02x", hmac_resultado[i]);
    }
    saida_buffer[64] = '\0'; // Adiciona o terminador nulo

    ESP_LOGI(TAG, "Cálculo da contrachave concluído com sucesso.");
    return ESP_OK;
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    switch (event_id) {
    case WIFI_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case WIFI_EVENT_STA_CONNECTED:
        ESP_LOGI(TAG, "WiFi connected");
        break;
    case WIFI_EVENT_STA_DISCONNECTED:
        ESP_LOGI(TAG, "WiFi disconnected, reconnecting...");
        esp_wifi_connect();
        break;
    default:
        break;
    }
}

static void wifi_init_sta(void) {
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, NULL);
    esp_wifi_start();

    ESP_LOGI(TAG, "WiFi initialization done.");
}

static void websocket_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    esp_websocket_event_data_t *data = (esp_websocket_event_data_t *)event_data;

    switch (event_id) {
    case WEBSOCKET_EVENT_CONNECTED:
        ESP_LOGI(TAG, "WebSocket connected");
        break;

    case WEBSOCKET_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "WebSocket disconnected");
        break;

    case WEBSOCKET_EVENT_DATA: {
        if (data->op_code == 0x9 || data->op_code == 0xA) {
            return; // Dar Return pq é PING ou PONG
        }
        // ESP_LOGI(TAG, "Received data: %.*s", data->data_len, (char *)data->data_ptr);
        JsonDocument rcvData;
        mpack_tree_t tree;
        mpack_tree_init_data(&tree, data->data_ptr, data->data_len);
        mpack_tree_parse(&tree);
        mpack_node_t root = mpack_tree_root(&tree);

        rcvData = deserializeMpackToJson(root);
        mpack_tree_destroy(&tree);
        ESP_LOGI(TAG, "Received data: %s", rcvData.as<std::string>().c_str());

        if (rcvData["type"].as<std::string>() == "greeting") {
            ESP_LOGI(TAG, "Greeting detected, preparing JSON...");

            JsonDocument doc;
            doc["type"] = "greeting";

            doc["content"].to<JsonObject>();
            doc["content"]["id"] = 100015;
            doc["content"]["name"] = "Brise15";
            doc["content"]["kind"] = 0;

            char calcKey[65]; // 64 chars para hex + 1 para '\0'
            calculate_key(rcvData["content"][1].as<const char *>(), "100015-ChaveSecreta", calcKey, sizeof(calcKey));
            doc["content"]["key"] = std::string(calcKey);

            sendWebSockMessage(doc);
        }
        else if (rcvData["type"].as<std::string>() == "greeting-reply") {
            JsonDocument doc;
            doc["type"] = "sub";

            doc["content"].to<JsonObject>();

            sendWebSockMessage(doc);
        }
        break;
    }

    case WEBSOCKET_EVENT_ERROR:
        ESP_LOGE(TAG, "WebSocket error occurred");
        break;

    default:
        break;
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "Starting BRISE2 client...");

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init_sta();

    ESP_LOGI(TAG, "Connecting to WiFi...");
    vTaskDelay(5000 / portTICK_PERIOD_MS);

    esp_websocket_client_config_t websocket_cfg = {
        .uri = "wss://brise2-debug.agst.com.br/ws",
        .crt_bundle_attach = esp_crt_bundle_attach,
    };

    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    size_t min_free_heap = heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);
    size_t largest_free_block = heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);

    ESP_LOGI(TAG, "Free heap: %u bytes", (unsigned)free_heap);
    ESP_LOGI(TAG, "Minimum ever free heap: %u bytes", (unsigned)min_free_heap);
    ESP_LOGI(TAG, "Largest free block: %u bytes", (unsigned)largest_free_block);

    client = esp_websocket_client_init(&websocket_cfg);

    esp_websocket_register_events(client, WEBSOCKET_EVENT_ANY, websocket_event_handler, NULL);

    esp_websocket_client_start(client);

    while (1) {
        //     // O evento de dados é tratado na callback, aqui só mantemos a task viva
        vTaskDelay(30000 / portTICK_PERIOD_MS);

        JsonDocument doc;
        doc["type"] = "pub";

        doc["content"].to<JsonObject>();
        doc["content"]["numero"] = 0;
        doc["content"]["hw"] = "OLA MUNDO";
        doc["content"]["bool"] = true;

        sendWebSockMessage(doc);

        //     free_heap = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
        //     min_free_heap = heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);
        //     largest_free_block = heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);

        //     ESP_LOGI(TAG, "Free heap: %u bytes", (unsigned)free_heap);
        //     ESP_LOGI(TAG, "Minimum ever free heap: %u bytes", (unsigned)min_free_heap);
        //     ESP_LOGI(TAG, "Largest free block: %u bytes", (unsigned)largest_free_block);
    }

    // Nunca alcançado, mas caso queira parar e limpar:
    // esp_websocket_client_stop(client);
    // esp_websocket_client_destroy(client);
}
