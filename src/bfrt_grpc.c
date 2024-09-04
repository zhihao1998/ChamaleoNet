#include "tsdn.h"

static PyObject *pModule, *pClass, *pInstance;

void bfrt_clear_tables()
{
	PyObject *pArgs, *pRes, *pFunc;
	pFunc = PyObject_GetAttrString(pInstance, "clear_tables"); 
	pArgs = Py_BuildValue("()"); 
	pRes = PyEval_CallObject(pFunc, pArgs);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
}

/* Initialze Grpc object */
void bfrt_grpc_init()
{	
	PyObject *pArgs;
	Py_Initialize();
	PyRun_SimpleString("import sys");
	PyRun_SimpleString("sys.path.append('./bfrt_grpc')");

	pModule = PyImport_ImportModule("bfrt_grpc_server");
	assert(pModule != NULL);
	/* Call Py_INCREF() for objects that you want to keep around for a while.  
	 * A pointer to an object that has been INCREFed is said to be protected. */
	Py_INCREF(pModule);

	pClass = PyObject_GetAttrString(pModule, "Bfrt_GRPC_Server"); /* fetch module.class */
	assert(pClass != NULL);
	Py_INCREF(pClass);

	/* Instantiate the class */
	pArgs = Py_BuildValue("()"); /* create empty argument tuple */
	pInstance = PyEval_CallObject(pClass, pArgs); 
	assert(pInstance != NULL);
	Py_INCREF(pInstance);

	bfrt_clear_tables();
}

void bfrt_grpc_destroy()
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
int bfrt_tcp_flow_add_with_drop(in_addr src_ip, in_addr dst_ip, u_short src_port, u_short dst_port)
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	char ip_src_addr_str[INET_ADDRSTRLEN], ip_dst_addr_str[INET_ADDRSTRLEN];
	int ret = 0;

	inet_ntop(AF_INET, &(src_ip), ip_src_addr_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(dst_ip), ip_dst_addr_str, INET_ADDRSTRLEN);

	pFunc = PyObject_GetAttrString(pInstance, "tcp_flow_add_with_drop"); 
	pArgs = Py_BuildValue("(ssii)", ip_src_addr_str, ip_dst_addr_str, ntohs(src_port), ntohs(dst_port)); 
	pRes = PyEval_CallObject(pFunc, pArgs);
	assert(pRes != NULL);	 
	PyArg_Parse(pRes, "i", &ret);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
	return ret;
}

/* UDP Flow Table */
int bfrt_udp_flow_add_with_drop(in_addr src_ip, in_addr dst_ip, u_short src_port, u_short dst_port)
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	char ip_src_addr_str[INET_ADDRSTRLEN], ip_dst_addr_str[INET_ADDRSTRLEN];
	int ret = 0;

	inet_ntop(AF_INET, &(src_ip), ip_src_addr_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(dst_ip), ip_dst_addr_str, INET_ADDRSTRLEN);

	pFunc = PyObject_GetAttrString(pInstance, "udp_flow_add_with_drop"); 
	pArgs = Py_BuildValue("(ssii)", ip_src_addr_str, ip_dst_addr_str, ntohs(src_port), ntohs(dst_port)); 
	pRes = PyEval_CallObject(pFunc, pArgs);	 
	PyArg_Parse(pRes, "i", &ret);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
	return ret;
}

/* ICMP Flow Table */
int bfrt_icmp_flow_add_with_drop(in_addr src_ip, in_addr dst_ip)
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	char ip_src_addr_str[INET_ADDRSTRLEN], ip_dst_addr_str[INET_ADDRSTRLEN];
	int ret = 0;

	inet_ntop(AF_INET, &(src_ip), ip_src_addr_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(dst_ip), ip_dst_addr_str, INET_ADDRSTRLEN);

	pFunc = PyObject_GetAttrString(pInstance, "icmp_flow_add_with_drop"); 
	pArgs = Py_BuildValue("(ss)", ip_src_addr_str, ip_dst_addr_str); 
	pRes = PyEval_CallObject(pFunc, pArgs);	
	PyArg_Parse(pRes, "i", &ret);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
	return ret;
}

int bfrt_print_tables_info()
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	int ret = -1;

	pFunc = PyObject_GetAttrString(pInstance, "print_tables_info"); 
	pArgs = Py_BuildValue("()"); 
	pRes = PyEval_CallObject(pFunc, pArgs);	
	// PyArg_Parse(pRes, "i", &ret);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
	return ret;
}