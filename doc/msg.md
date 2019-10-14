# DDOS检测

## 消息类型

* [策略消息接口](#Policy)
* [聚合数据接口](#Statis)

<a id="Policy" />

## 策略消息接口

因为性能和资源消耗的原因，QNSM不会持续输出所有类型的聚合数据。因此需要策略消息接口控制聚合数据输出。

QNSM不提供数据分析功能，因此策略消息需要有独立的分析中心下发。

一般情况下，这个策略是基于DDOS攻击事件的开始和结束。

使用`qnsm_command` kafka topic。

### dump策略消息

DDOS事件开始, 发送`ip_dump_pkt_enable`消息.

DDOS事件结束, 发送`ip_dump_pkt_disable`消息.

```json
{

"op":"ip_dump_pkt_enable",

"content":

[

{"idc":"dc_xxx", "proto":"udp", "vip":"A.B.C.D", "vport":"any"},

{"idc":"dc_xxx", "proto":"tcp", "vip":"E.F.G.H", "vport":"80"}

]

}
```
`op` 表示cmd类型，ip_dump_pkt_enable/ip_dump_pkt_disable.

`idc` 表示IDC名, 与配置文件qnsm_edge.xml的dc配置项相同.

`proto` 包括'tcp', 'udp', 'any', 忽略大小写. 

`vip` 表示服务ip.

`vport` 表示服务端口, 缺省填any即可.

### vip+sport策略消息

Udp flood事件开始, 发送`ip_sport_statis_enable`消息.

Udp flood事件结束, 发送`ip_sport_statis_disable`消息.
```json
{

"op":"ip_sport_statis_enable",

"content":

[

{"idc":"dc_xxx", "ip":"A.B.C.D"}

]

}
```

`ip` 表示监控的服务IP.

### DFI/DPI消息

分析中心基于vip+sport聚合数据，得出udp flood的攻击源端口，进而下发DFI策略消息。

如果分析中心不需要QNSM DFI处理，不下发该消息即可。

```json
{
    "id":"1",
    "op":"ddos_type_check",
    "content":{
        "vip":"A.B.C.D",
        "idc":"dc_xxx",
        "sport":20
    }
}
```

`id` 表示消息id或者DDOS事件ID。

`op` 表示命令类型，这里是ddos_type_check.

`sport` 表示攻击源端口.

QNSM DFI处理结束后，发送结果至`qnsm_command_ack` kafka topic
```json
{
    "req_id":"1",
    "sender":"dc_xxx:qnsm-instance-1",
    "op":"ddos_type_check",
    "content":

   {
        "vip":"A.B.C.D",
        "idc":"dc_xxx",
        "sport":20,
        "app_protocol":

         [
               {   

                   "app":"memcache",
                    "bits":2000,
                    "pkts":20
                },
                {  

                    "app":"other",
                    "bits":1000,
                    "pkts":10
                }
        ]
    }
}
```
现在我们提供以下协议的DFI

| app     |
| :-----: |
| dns     |
| ntp     |
| ssdp    |
| memcache|

<a id="Statis" />

## 聚合数据消息

### VIP_AGG
消费`qnsm_vip_agg`，基于VIP粒度进行DDOS攻击检测。

```json
{

        "metric":       "dip_traffic",

        "data": [{

                        "ip":   "A.B.C.D",

                        "biz_name":     "qiyi1",

                        "dc":   "dc_xxx",

                        "metric":       "dip_traffic",

                        "from_time":    1512553858,

                        "to_time":      1512553868,

                        "data": [{

                                        "type": "TOTAL",

                                        "pps_in":       24932,

                                        "bps_in":       21419802,

                                        "pps_out":      55252,

                                        "bps_out":      617124794

                                }, {

                                        "type": "TCP",

                                        "pps_in":       24700,

                                        "bps_in":       21181450,

                                        "pps_out":      54998,

                                        "bps_out":      616759703

                                }, {

                                        "type": "SYN",

                                        "pps_in":       839,

                                        "bps_in":       621808,

                                        "pps_out":      1,

                                        "bps_out":      851

                                }, {

                                        "type": "ACK",

                                        "pps_in":       21352,

                                        "bps_in":       14611471,

                                        "pps_out":      50667,

                                        "bps_out":      600860385

                                }, {

                                        "type": "FIN",

                                        "pps_in":       540,

                                        "bps_in":       358287,

                                        "pps_out":      604,

                                        "bps_out":      722744

                                }, {

                                        "type": "RST",

                                        "pps_in":       257,

                                        "bps_in":       164868,

                                        "pps_out":      642,

                                        "bps_out":      411072

                                }, {

                                        "type": "SYNACK",

                                        "pps_in":       1,

                                        "bps_in":       809,

                                        "pps_out":      854,

                                        "bps_out":      590164

                                }, {

                                        "type": "PSHACK",

                                        "pps_in":       1704,

                                        "bps_in":       5420172,

                                        "pps_out":      2224,

                                        "bps_out":      14169360

                                }, {

                                        "type": "OTHER_FLAG",

                                        "pps_in":       4,

                                        "bps_in":       4033,

                                        "pps_out":      4,

                                        "bps_out":      5124

                                }, {

                                        "type": "UDP",

                                        "pps_in":       222,

                                        "bps_in":       228468,

                                        "pps_out":      246,

                                        "bps_out":      357940

                                }, {

                                        "type": "DNS_REPLY",

                                        "pps_in":       105,

                                        "bps_in":       144456,

                                        "pps_out":      116,

                                        "bps_out":      199792

                                }, {

                                        "type": "DNS_QUERY",

                                        "pps_in":       11,

                                        "bps_in":       14760,

                                        "pps_out":      0,

                                        "bps_out":      0

                                }, {

                                        "type": "NTP",

                                        "pps_in":       0,

                                        "bps_in":       88,

                                        "pps_out":      0,

                                        "bps_out":      176

                                }, {

                                        "type": "SSDP_REP",

                                        "pps_in":       0,

                                        "bps_in":       0,

                                        "pps_out":      0,

                                        "bps_out":      173

                                }, {

                                        "type": "ICMP",

                                        "pps_in":       9,

                                        "bps_in":       9883,

                                        "pps_out":      7,

                                        "bps_out":      7150

                                }]

                }]

}
```

### VIP+DPORT
消费`qnsm_vip_dport` kafka topic获取vip+dport的聚合数据.

提供top 20的目的端口数据。

```json
{
    "ip":"A.B.C.D",
    "dc":"dc_yyy",
    "time":1521114225,
    "metric":"dport",
    "data":[
        {
            "port_id":47595,
            "pkts":3242,
            "bits":35590736
        },
        {
            "port_id":49661,
            "pkts":3486,
            "bits":36820456
        },
        {
            "port_id":37281,
            "pkts":3292,
            "bits":35796568
        },
        {
            "port_id":33720,
            "pkts":3812,
            "bits":40361376
        },
        {
            "port_id":50409,
            "pkts":3950,
            "bits":43929968
        },
        {
            "port_id":50747,
            "pkts":3377,
            "bits":37921208
        },
        {
            "port_id":59452,
            "pkts":3671,
            "bits":39972712
        },
        {
            "port_id":33038,
            "pkts":4081,
            "bits":44097968
        },
        {
            "port_id":50315,
            "pkts":3974,
            "bits":44093320
        },
        {
            "port_id":54375,
            "pkts":4108,
            "bits":46890480
        },
        {
            "port_id":55872,
            "pkts":4157,
            "bits":44990752
        },
        {
            "port_id":57069,
            "pkts":3537,
            "bits":39167640
        },
        {
            "port_id":48447,
            "pkts":9032,
            "bits":106400624
        },
        {
            "port_id":52040,
            "pkts":4926,
            "bits":55219112
        },
        {
            "port_id":44851,
            "pkts":3674,
            "bits":41650960
        }
    ]
}
```

### VIP+SPORT

Vip+sport聚合数据默认不输出，基于vip+sport策略消息控制。

消费`qnsm_vip_sport` kafka topic。

```json
{
    "ip":"A.B.C.D",
    "dc":"dc_zzz",
    "time":1521113673,
    "metric":"sport",
    "data":[
        {
            "port_id":5760,
            "pkts":45,
            "bits":29520
        },
        {
            "port_id":12928,
            "pkts":47,
            "bits":30832
        },
        {
            "port_id":27312,
            "pkts":28,
            "bits":29664
        },
        {
            "port_id":12352,
            "pkts":48,
            "bits":31488
        },
        {
            "port_id":4736,
            "pkts":48,
            "bits":31488
        },
        {
            "port_id":1729,
            "pkts":48,
            "bits":31488
        },
        {
            "port_id":5056,
            "pkts":47,
            "bits":30832
        },
        {
            "port_id":15104,
            "pkts":52,
            "bits":34112
        },
        {
            "port_id":18693,
            "pkts":24,
            "bits":33680
        },
        {
            "port_id":50083,
            "pkts":49,
            "bits":32144
        },
        {
            "port_id":15040,
            "pkts":62,
            "bits":40672
        },
        {
            "port_id":60023,
            "pkts":23,
            "bits":31504
        },
        {
            "port_id":4427,
            "pkts":19,
            "bits":42800
        }
    ]
}
```

### SIP AGG

源IP聚合数据默认不输出，基于dump策略消息控制。

消费`qnsm_sip_agg` kafka topic。

```json
{
    "metric":"sip_in",
    "data":[
        {
            "ip":"A.B.C.D",
            "dc":"dc_ddd",
            "metric":"sip_in",
            "time":1521430675,
            "data":[
                {
                    "vip":"vip1.vip1.vip1.vip1",
                    "tcp_pps_in":0,
                    "tcp_bps_in":0,
                    "tcp_pps_out":0,
                    "tcp_bps_out":0,
                    "udp_pps_in":0,
                    "udp_bps_in":392,
                    "udp_pps_out":0,
                    "udp_bps_out":0
                },
                {
                    "vip":"vip2.vip2.vip2.vip2",
                    "tcp_pps_in":0,
                    "tcp_bps_in":0,
                    "tcp_pps_out":0,
                    "tcp_bps_out":0,
                    "udp_pps_in":0,
                    "udp_bps_in":328,
                    "udp_pps_out":0,
                    "udp_bps_out":0
                }
            ]
        },
        {
            "ip":"sip2.sip2.sip2.sip2",
            "dc":"dc_ddd",
            "metric":"sip_in",
            "time":1521430665,
            "data":[
                {
                    "vip":"vip3.vip3.vip3.vip3",
                    "tcp_pps_in":1,
                    "tcp_bps_in":1226,
                    "tcp_pps_out":0,
                    "tcp_bps_out":0,
                    "udp_pps_in":0,
                    "udp_bps_in":0,
                    "udp_pps_out":0,
                    "udp_bps_out":0
                }
            ]
        }
    ]
}
```

### Sample flow
Flow定义为单向具有公共属性的数据包序列。

消费`qnsm_sample_flow`kafka topic。

```json
{
    "dc":"dc_aaa",
    "sampling_interval":4000,
    "timestamp":1557718926,
    "ip_protocol":6,
    "ip_version":4,
    "src_ip":"A.B.C.D",
    "src_port":52058,
    "dst_ip":"E.F.G.H",
    "dst_port":80,
    "direction":1,
    "tcp_flags":16,
    "icmp_type":0,
    "packets":2,
    "out_bytes":2868
}
```

direction: 1 表示出方向, 0表示入方向。

# IDPS

## 事件接口

消费`nsm_event` kafka topic。

```json
{
    "timestamp":"2019-08-23T17:06:35.284049+0800",
    "flow_id":1854917666668179,
    "event_type":"alert",
    "src_ip":"A.B.C.D",
    "src_port":60013,
    "dest_ip":"78.46.222.60",
    "dest_port":457,
    "proto":"TCP",
    "alert":{
        "action":"allowed",
        "gid":1,
        "signature_id":2024792,
        "rev":4,
        "signature":"ET POLICY Cryptocurrency Miner Checkin",
        "category":"attack_medium",
        "severity":2,
        "metadata":{
            "updated_at":[
                "2018_06_15"
            ],
            "created_at":[
                "2017_10_02"
            ],
            "signature_severity":[
                "Minor"
            ],
            "deployment":[
                "Perimeter"
            ],
            "attack_target":[
                "Client_Endpoint"
            ],
            "affected_product":[
                "Windows_XP_Vista_7_8_10_Server_32_64_Bit"
            ],
            "former_category":[
                "POLICY"
            ]
        }
    },
    "flow":{
        "pkts_toserver":3,
        "pkts_toclient":1,
        "bytes_toserver":401,
        "bytes_toclient":66,
        "start":"2019-08-23T17:06:35.065171+0800"
    },
    "payload_hex":"7B226964223A312C226A736F6E727063223A22322E30222C226D6574686F64223A226C6F67696E222C22706172616D73223A7B226C6F67696E223A2278222C2270617373223A2278222C226167656E74223A22584D5269675C2F322E31332E31202857696E646F7773204E542031302E303B2057696E36343B2078363429206C696275765C2F312E32342E31206D7376635C2F32303137222C22616C676F223A5B22636E5C2F776F77222C22636E5C2F72222C22636E5C2F32222C22636E5C2F31222C22636E5C2F30222C22636E5C2F78746C222C22636E225D7D7D0A",
    "stream":0,
    "host":"sensor-name"
}
```