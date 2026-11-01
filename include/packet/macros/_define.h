#define STR_IMPL(s) #s
#define STR(s) STR_IMPL(s)
#define CONCAT_IMPL(a, b) a##b
#define CONCAT(a, b) CONCAT_IMPL(a, b)
#define PACKET_T CONCAT(DEFINE_PACKET_NAME, _t)
#define PACKET_T_SER CONCAT(DEFINE_PACKET_NAME, _serialise)
#define PACKET_T_DE CONCAT(DEFINE_PACKET_NAME, _deserialise)
#define PACKET_T_PRINT CONCAT(DEFINE_PACKET_NAME, _print)
