#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <string.h>
#include <assert.h>
#include <pthread.h> 
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#include <Python.h>

typedef struct in_addr in_addr;

static PyObject *pModule, *pClass, *pInstance;

/* Initialze Grpc object */
int tf_grpc_init()
{	
	PyObject *pArgs;
	Py_Initialize();
	PyRun_SimpleString("import sys");
	PyRun_SimpleString("sys.path.append('./tf_grpc')");

	pModule = PyImport_ImportModule("tf_grpc_server");
	assert(pModule != NULL);
	/* Call Py_INCREF() for objects that you want to keep around for a while.  
	 * A pointer to an object that has been INCREFed is said to be protected. */
	Py_INCREF(pModule);

	pClass = PyObject_GetAttrString(pModule, "TfGRPCServer"); /* fetch module.class */
	assert(pClass != NULL);
	Py_INCREF(pClass);

	/* Instantiate the class */
	pArgs = Py_BuildValue("()"); /* create empty argument tuple */
	pInstance = PyEval_CallObject(pClass, pArgs); 
	assert(pInstance != NULL);
	Py_INCREF(pInstance);
}

int tf_grpc_destroy()
{
	/* Clean up */
	assert(pInstance != NULL);
	assert(pClass != NULL);
	assert(pModule != NULL);

	Py_DECREF(pInstance);
	Py_DECREF(pClass);
	Py_DECREF(pModule);
	Py_Finalize();
}

/* TCP Flow Table */
int tf_tcp_flow_add_with_drop(in_addr src_ip, in_addr dst_ip, u_short src_port, u_short dst_port)
{
	PyObject *pArgs, *pRes, *pFunc;
	char ip_src_addr_str[INET_ADDRSTRLEN], ip_dst_addr_str[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(src_ip), ip_src_addr_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(dst_ip), ip_dst_addr_str, INET_ADDRSTRLEN);

	pFunc = PyObject_GetAttrString(pInstance, "tcp_flow_add_with_drop"); 
	pArgs = Py_BuildValue("(ssii)", ip_src_addr_str, ip_dst_addr_str, src_port, dst_port); 
	pRes = PyEval_CallObject(pFunc, pArgs);	 
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
}

int tf_tcp_flow_add_with_send(in_addr src_ip, in_addr dst_ip, u_short src_port, u_short dst_port, u_short egress_port)
{
	PyObject *pArgs, *pRes, *pFunc;
	char ip_src_addr_str[INET_ADDRSTRLEN], ip_dst_addr_str[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(src_ip), ip_src_addr_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(dst_ip), ip_dst_addr_str, INET_ADDRSTRLEN);

	pFunc = PyObject_GetAttrString(pInstance, "tcp_flow_add_with_send"); 
	assert(pFunc != NULL);
	pArgs = Py_BuildValue("(ssiii)", ip_src_addr_str, ip_dst_addr_str, src_port, dst_port, egress_port); 
	assert(pArgs != NULL);
	pRes = PyEval_CallObject(pFunc, pArgs);	 
	assert(pRes != NULL);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
}


PyObject *import_name(const char *modname, const char *symbol)
{
	PyObject *u_name, *module;
	u_name = PyUnicode_FromString(modname);
	module = PyImport_Import(u_name);
	Py_DECREF(u_name);
	return PyObject_GetAttrString(module, symbol);
}

/* Simple embedding example */
int main()
{
	tf_grpc_init();

	in_addr src_ip, dst_ip;
	inet_aton("10.0.0.1", &(src_ip));
	inet_aton("10.0.0.2", &(dst_ip));

	u_short src_port = 80;
	u_short dst_port = 81;
	u_short egress_port = 1;

	tf_tcp_flow_add_with_drop(src_ip, dst_ip, src_port, dst_port);
	tf_tcp_flow_add_with_send(src_ip, dst_ip, src_port, dst_port, egress_port);

	tf_grpc_destroy();

	return 0;
}