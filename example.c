#include <zmq.h>

int main(void) {
    void *ctx = zmq_ctx_new();
    void *rep = zmq_socket(ctx, ZMQ_REP);
    zmq_bind(rep, "tcp://127.0.0.1:6969");
    while (1) {
        zmq_msg_t msg;
        zmq_msg_init(&msg);
        zmq_msg_recv(&msg, rep, 0);
        zmq_msg_send(&msg, rep, 0);
    }
}
