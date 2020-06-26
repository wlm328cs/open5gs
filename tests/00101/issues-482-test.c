/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "test-5gc.h"

static void test1_func(abts_case *tc, void *data)
{
    int rv;
    ogs_socknode_t *ngap;
    ogs_socknode_t *gtpu;
    ogs_pkbuf_t *gmmbuf;
    ogs_pkbuf_t *gsmbuf;
    ogs_pkbuf_t *nasbuf;
    ogs_pkbuf_t *sendbuf;
    ogs_pkbuf_t *recvbuf;
    ogs_ngap_message_t message;
    int i;
    int msgindex = 0;

    ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
    test_ue_t test_ue;
    test_sess_t test_sess;

    uint8_t tmp[OGS_MAX_SDU_LEN];

    const char *_ng_setup_response = "2015"
        "0055000004000100 311700616d66312e 61737472692e616d 662e3567632e6d6e"
        "6330312e6d636330 30312e336770706e 6574776f726b2e6f 7267006000080000"
        "00f1100100410056 4001640050000800 00f11000000008";

    const char *_identity_request = "0004"
        "4018000003000a00 0200010055000200 0000260005047e00 5b01";

    const char *_authentication_request1 = "0004"
        "403e000003000a00 0200010055000200 000026002b2a7e00 5600020000213a1f"
        "a0f51fe50f324f85 22b220fc62a22010 2f9a84aca0608000 9135d2ae4d6f51ad";
    const char *_authentication_request2 = "0004"
        "403e000003000a00 0200010055000200 000026002b2a7e00 560102000021cc55"
        "39bf72824c879e47 e73efc8850212010 5c9bc7e54bcd8000 55e239e441bec5e3";

    const char *_security_mode_command = "0004"
        "4026000003000a00 0200010055000200 0000260013127e03 d950da91007e005d"
        "020102f0f0360102";

    const char *_registration_accept = "000e"
        "00808f000008000a 0002000100550002 0000006e00060404 00100400001c0007"
        "0000f11001004100 0000020001007700 091c000e00000000 0000005e002097ab"
        "0be862c90eff91e7 d1e2720243244462 d933a5e01fefc882 048a8d2dbf630026"
        "40302f7e021fc086 2d017e0042010177 000bf200f1100100 4101000001540740"
        "00f1100000511502 010121030100005e 0106";

    const char *_k_string = "00112233445566778899aabbccddeeff";
    uint8_t k[OGS_KEY_LEN];
    const char *_opc_string = "279eb54971771559879284fddde3ee0c";
    uint8_t opc[OGS_KEY_LEN];

    mongoc_collection_t *collection = NULL;
    bson_t *doc = NULL;
    int64_t count = 0;
    bson_error_t error;
    const char *json =
      "{"
        "\"_id\" : { \"$oid\" : \"597223158b8861d7605378c6\" }, "
        "\"imsi\" : \"001010000000001\","
        "\"ambr\" : { "
          "\"uplink\" : { \"$numberLong\" : \"1\" }, "
          "\"downlink\" : { \"$numberLong\" : \"1\" } "
        "},"
        "\"pdn\" : ["
          "{"
            "\"apn\" : \"internet\", "
            "\"_id\" : { \"$oid\" : \"597223158b8861d7605378c7\" }, "
            "\"ambr\" : {"
              "\"uplink\" : { \"$numberLong\" : \"1024000\" }, "
              "\"downlink\" : { \"$numberLong\" : \"1024000\" } "
            "},"
            "\"qos\" : { "
              "\"qci\" : 9, "
              "\"arp\" : { "
                "\"priority_level\" : 8,"
                "\"pre_emption_vulnerability\" : 1, "
                "\"pre_emption_capability\" : 1"
              "} "
            "}, "
            "\"type\" : 2"
          "}"
        "],"
        "\"security\" : { "
          "\"k\" : \"00112233445566778899aabbccddeeff\", "
          "\"opc\" : \"279eb54971771559879284fddde3ee0c\", "
          "\"amf\" : \"8000\", "
          "\"sqn\" : { \"$numberLong\" :  \"32\" } "
        "}, "
        "\"subscribed_rau_tau_timer\" : 12,"
        "\"network_access_mode\" : 2, "
        "\"subscriber_status\" : 0, "
        "\"access_restriction_data\" : 32, "
        "\"__v\" : 0 "
      "}";

    /* Setup Test UE & Session Context */
    memset(&test_ue, 0, sizeof(test_ue));
    memset(&test_sess, 0, sizeof(test_sess));
    test_sess.test_ue = &test_ue;
    test_ue.sess = &test_sess;

    test_ue.nas.registration.type = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    test_ue.nas.registration.follow_on_request = 1;
    test_ue.nas.registration.value = OGS_NAS_5GS_REGISTRATION_TYPE_INITIAL;

    memset(&mobile_identity_suci, 0, sizeof(mobile_identity_suci));

    mobile_identity_suci.h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    mobile_identity_suci.h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    ogs_nas_from_plmn_id(&mobile_identity_suci.nas_plmn_id,
            &test_self()->tai.plmn_id);
    mobile_identity_suci.routing_indicator1 = 0;
    mobile_identity_suci.routing_indicator2 = 0xf;
    mobile_identity_suci.routing_indicator3 = 0xf;
    mobile_identity_suci.routing_indicator4 = 0xf;
    mobile_identity_suci.protection_scheme_id = OGS_NAS_5GS_NULL_SCHEME;
    mobile_identity_suci.home_network_pki_value = 0;
    mobile_identity_suci.scheme_output[0] = 0;
    mobile_identity_suci.scheme_output[1] = 0;
    mobile_identity_suci.scheme_output[2] = 0;
    mobile_identity_suci.scheme_output[3] = 0;
    mobile_identity_suci.scheme_output[4] = 0x10;

    test_ue_set_mobile_identity_suci(&test_ue, &mobile_identity_suci, 13);

    test_ue.nas.access_type = OGS_ACCESS_TYPE_3GPP;
    test_ue.abba_len = 2;

    OGS_HEX(_k_string, strlen(_k_string), test_ue.k);
    OGS_HEX(_opc_string, strlen(_opc_string), test_ue.opc);

    test_sess.psi = 5;
    test_sess.pti = 1;
    test_sess.pdu_session_type = OGS_PDU_SESSION_TYPE_IPV4V6;
    test_sess.dnn = (char *)"internet";

    memset(&test_sess.gnb_n3_ip, 0, sizeof(test_sess.gnb_n3_ip));
    test_sess.gnb_n3_ip.ipv4 = true;
    test_sess.gnb_n3_ip.addr = inet_addr("127.0.0.5");
    test_sess.gnb_n3_teid = 0;

    /* gNB connects to AMF */
    ngap = testgnb_ngap_client("127.0.0.2");
    ABTS_PTR_NOTNULL(tc, ngap);

    /* gNB connects to UPF */
    gtpu = testgnb_gtpu_server("127.0.0.5");
    ABTS_PTR_NOTNULL(tc, gtpu);

    /* Send NG-Setup Reqeust */
    sendbuf = testngap_build_ng_setup_request(0xce, 32);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive NG-Setup Response */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(&test_ue, recvbuf);
    ABTS_TRUE(tc, memcmp(recvbuf->data,
        OGS_HEX(_ng_setup_response, strlen(_ng_setup_response), tmp),
        recvbuf->len) == 0);

    /********** Insert Subscriber in Database */
    collection = mongoc_client_get_collection(
        ogs_mongoc()->client, ogs_mongoc()->name, "subscribers");
    ABTS_PTR_NOTNULL(tc, collection);
    doc = BCON_NEW("imsi", BCON_UTF8(test_ue.imsi));
    ABTS_PTR_NOTNULL(tc, doc);

    count = mongoc_collection_count (
        collection, MONGOC_QUERY_NONE, doc, 0, 0, NULL, &error);
    if (count) {
        ABTS_TRUE(tc, mongoc_collection_remove(collection,
                MONGOC_REMOVE_SINGLE_REMOVE, doc, NULL, &error))
    }
    bson_destroy(doc);

    doc = bson_new_from_json((const uint8_t *)json, -1, &error);;
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_TRUE(tc, mongoc_collection_insert(collection,
                MONGOC_INSERT_NONE, doc, NULL, &error));
    bson_destroy(doc);

    doc = BCON_NEW("imsi", BCON_UTF8(test_ue.imsi));
    ABTS_PTR_NOTNULL(tc, doc);
    do {
        count = mongoc_collection_count (
            collection, MONGOC_QUERY_NONE, doc, 0, 0, NULL, &error);
    } while (count == 0);
    bson_destroy(doc);

    /* To start RAN-UE-NGAP-ID : 0 */
    test_ue.ran_ue_ngap_id = -1;
    test_self()->nr_cgi.cell_id = 0x000000ce7;

    /* Send Registration request */
    test_ue.registration_request_type.guti = 1;
    gmmbuf = testgmm_build_registration_request(&test_ue, NULL);
    ABTS_PTR_NOTNULL(tc, gmmbuf);

    test_ue.registration_request_type.requested_nssai = 1;
    test_ue.registration_request_type.last_visited_registered_tai = 1;
    test_ue.registration_request_type.ue_usage_setting = 1;
    nasbuf = testgmm_build_registration_request(&test_ue, NULL);
    ABTS_PTR_NOTNULL(tc, nasbuf);

    sendbuf = testngap_build_initial_ue_message(&test_ue, gmmbuf, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Indentity request */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(&test_ue, recvbuf);

    /* Send Identity response */
    gmmbuf = testgmm_build_identity_response(&test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(&test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_TRUE(tc, memcmp(recvbuf->data,
        OGS_HEX(_identity_request, strlen(_identity_request), tmp),
        recvbuf->len) == 0);

    /* Receive Authentication request */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(&test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_TRUE(tc, memcmp(recvbuf->data,
        OGS_HEX(_authentication_request1,
            strlen(_authentication_request1), tmp),
        recvbuf->len) == 0);

    /* Send Authentication failure - SYNCH failure */
    gmmbuf = testgmm_build_authentication_failure(
            &test_ue, OGS_5GMM_CAUSE_SYNCH_FAILURE, 0x1f60);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(&test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Authentication request */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(&test_ue, recvbuf);
    ABTS_TRUE(tc, memcmp(recvbuf->data,
        OGS_HEX(_authentication_request2,
            strlen(_authentication_request2), tmp),
        recvbuf->len) == 0);

    /* Send Authentication response */
    gmmbuf = testgmm_build_authentication_response(&test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(&test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Security mode command */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(&test_ue, recvbuf);
    ABTS_TRUE(tc, memcmp(recvbuf->data,
        OGS_HEX(_security_mode_command, strlen(_security_mode_command), tmp),
        recvbuf->len) == 0);

    /* Send Security mode complete */
    gmmbuf = testgmm_build_security_mode_complete(&test_ue, nasbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(&test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Initial context setup request */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(&test_ue, recvbuf);
    ABTS_TRUE(tc, memcmp(recvbuf->data,
        OGS_HEX(_registration_accept, strlen(_registration_accept), tmp),
        recvbuf->len) == 0);

    /* Send UE radio capability info indication */
    sendbuf = testngap_build_ue_radio_capability_info_indication(&test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send Initial context setup response */
    sendbuf = testngap_build_initial_context_setup_response(&test_ue, NULL);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(50);

    /* Send Registration complete */
    gmmbuf = testgmm_build_registration_complete(&test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(&test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Configuration update command */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(&test_ue, recvbuf);

#if 0
    /* Send PDU session establishment request */
    gsmbuf = testgsm_build_pdu_session_establishment_request(&test_sess);
    ABTS_PTR_NOTNULL(tc, gsmbuf);
    gmmbuf = testgmm_build_ul_nas_transport(&test_sess,
            OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, gsmbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(&test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive PDU session establishment accept */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(&test_ue, recvbuf);

    /* Send GTP-U ICMP Packet */
    rv = test_gtpu_build_ping(&sendbuf, &test_sess, "10.45.0.1");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    rv = testgnb_gtpu_send(gtpu, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(50);

    /* Send PDU session resource setup response */
    sendbuf = testngap_build_pdu_session_resource_setup_response(&test_sess);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(50);

    /* Receive GTP-U ICMP Packet */
    recvbuf = testgnb_gtpu_read(gtpu);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Send GTP-U ICMP Packet */
    rv = test_gtpu_build_ping(&sendbuf, &test_sess, "10.45.0.1");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    rv = testgnb_gtpu_send(gtpu, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet */
    recvbuf = testgnb_gtpu_read(gtpu);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    ogs_msleep(50);

    /* Send De-registration request */
    gmmbuf = testgmm_build_de_registration_request(&test_ue, 1);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(&test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive UE context release command */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(&test_ue, recvbuf);

    /* Send UE context release complete */
    sendbuf = testngap_build_ue_context_release_complete(&test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
#endif

    ogs_msleep(50);

    /********** Remove Subscriber in Database */
    doc = BCON_NEW("imsi", BCON_UTF8(test_ue.imsi));
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_TRUE(tc, mongoc_collection_remove(collection,
            MONGOC_REMOVE_SINGLE_REMOVE, doc, NULL, &error))
    bson_destroy(doc);

    mongoc_collection_destroy(collection);

    /* gNB disonncect from UPF */
    testgnb_gtpu_close(gtpu);

    /* gNB disonncect from AMF */
    testgnb_ngap_close(ngap);

    /* Clear Test UE Context */
    test_ue_remove(&test_ue);
}

abts_suite *test_issues_482(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test1_func, NULL);

    return suite;
}
