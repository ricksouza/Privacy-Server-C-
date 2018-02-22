/* A simple standalone XML-RPC server based on Abyss that contains a
   simple one-thread request processing loop.

   xmlrpc_sample_add_server.cpp is a server that does the same thing, but
   does it by running a full Abyss daemon in the background, so it has
   less control over how the requests are served.
*/

#include <cassert>
#include <iostream>

#include <xmlrpc-c/base.hpp>
#include <xmlrpc-c/registry.hpp>
#include <xmlrpc-c/server_abyss.hpp>
#include <xmlrpc-c/base.h>
#include <xmlrpc.h>
#include <xmlrpc-c/util.h>

#include "openssl/sha.h"
#include <stdio.h>
#include <string.h>
#include <PBC/Pairing.h>
#include <PBC/G1.h>
#include "systemparam.h"
#include <string>

using namespace std;

class sampleAddMethod : public xmlrpc_c::method {
public:

    sampleAddMethod() {
        // signature and help strings are documentation -- the client
        // can query this information with a system.methodSignature and
        // system.methodHelp RPC.
        this->_signature = "i:ii";  // method's arguments, result are integers
        this->_help = "This method adds two integers together";
    }

    void execute(xmlrpc_c::paramList const& paramList, xmlrpc_c::value * const retvalP) {

        int const addend(paramList.getInt(0));
        int const adder(paramList.getInt(1));

        paramList.verifyEnd(2);

        *retvalP = xmlrpc_c::value_int(addend + adder);
    }


};

class Cipher{
public:

	void openFile(char *filePath, char **buffer, int *size){

		FILE *file;
		long lSize;

		file = fopen(filePath, "rb");

		fseek(file, 0, SEEK_END);
		lSize = ftell(file);
		rewind(file);
		// allocate memory to contain the whole file:
		*buffer = (char*) (malloc(sizeof(char) * lSize));
		if (*buffer == NULL) {
			fputs("Memory error", stderr);
			exit(2);
		}
		// copy the file into the share_buffer:
		*size = fread(*buffer, 1, lSize, file);

		fclose(file);
	}

	Zr openShare(char *filePath, const Pairing& e){

		char *buffer;
		int size;

		openFile(filePath, &buffer, &size);

		char *tok;

		tok = strtok(buffer, ": \n");
		//if(tok != NULL)
		//	tok = strtok(NULL, ":");

		return Zr (e, (unsigned char *)tok, (size_t)size, 10);

	}

	unsigned char *generate_private_key(char *id, int *length){

		SystemParam sysparam("pairing.param", "system.param");

		const Pairing& e = sysparam.get_Pairing();

		vector<G1> sharesG1;
		vector<Zr> indices;

		G1 g1_publicKey;

		G1 msgHashG1;

		//hash_msg(msgHashG1, id, e);

		unsigned char *id_hash;
		id_hash = (unsigned char *) malloc(SHA_DIGEST_LENGTH);

		SHA1((unsigned char *) id, strlen(id), id_hash);

		msgHashG1 = G1(e, (void*) id_hash, SHA_DIGEST_LENGTH);

		Zr share_zr;
		G1 share_g1;
		share_zr = this->openShare("priv1", e);
		share_g1 = msgHashG1 ^ share_zr;

		element_s *e_share_g1;

		e_share_g1 = (element_s *)share_g1.getElement();

		int share_length = element_length_in_bytes(e_share_g1);

		*length = share_length;

		unsigned char *u_share_g1;

		u_share_g1 = (unsigned char *)calloc( share_length, sizeof(unsigned char));

		element_to_bytes(u_share_g1, e_share_g1);

		/**
		 * Teste
		 */
//		element_t teste;
//
//		element_init_G1(teste, (pairing_s *) e.getPairing());
//
//		element_from_bytes(teste, u_share_g1);
//
//		FILE *f_priv;
//		f_priv = fopen("shares/priv1", "w");
//
//		        //priv.dump(f_priv, "priv1", 10);
//		//element_out_str(f_priv, 10, e_share_g1);
//		element_out_str(f_priv, 10, teste);
//
//		fclose(f_priv);

		return u_share_g1;
	}

};

class authenticateMethod : public xmlrpc_c::method{

public:

	static int is_base64(char c) {
		if((c >= 'A' && c <= 'Z')  || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || (c == '+')             ||
			(c == '/')             || (c == '=')) {
			return 1;
		}
		return 0;
	}

	static unsigned char decode_base64_char(char c) {
		if(c >= 'A' && c <= 'Z')
			return(c - 'A');
		if(c >= 'a' && c <= 'z')
			return(c - 'a' + 26);
		if(c >= '0' && c <= '9')
			return(c - '0' + 52);
		if(c == '+')
			return 62;
		return 63;
	}

	static char encode_base64_char(unsigned char u) {
		if(u < 26)
			return 'A'+u;
		if(u < 52)
			return 'a'+(u-26);
		if(u < 62)
			return '0'+(u-52);
		if(u == 62)
			return '+';
		return '/';
	}

	unsigned char* decode64(const std::string string, int* ndata) {
		const char* src = string.c_str();
		int length = string.length();
		if(!length) {
			*ndata = 0;
			return NULL;
		}
		unsigned char *dest = NULL;
		if(src && *src) {
			dest = (unsigned char *)calloc(length, sizeof(char));
			unsigned char *p= dest;
			int k, l= length+1;
			unsigned char *buf= (unsigned char*) malloc(l);
			/* Ignore non base64 chars as per the POSIX standard */
			for(k=0, l=0; src[k]; k++) {
				if(is_base64(src[k])) {
					buf[l++]= src[k];
				}
			}
			for(k=0; k<l; k+=4) {
				char c1='A', c2='A', c3='A', c4='A';
				unsigned char b1=0, b2=0, b3=0, b4=0;
				c1= buf[k];
				if(k+1<l) {
					c2= buf[k+1];
				}
				if(k+2<l) {
					c3= buf[k+2];
				}
				if(k+3<l) {
					c4= buf[k+3];
				}
				b1= decode_base64_char(c1);
				b2= decode_base64_char(c2);
				b3= decode_base64_char(c3);
				b4= decode_base64_char(c4);
				*p++=((b1<<2)|(b2>>4) );
				if(c3 != '=') {
					*p++=(((b2&0xf)<<4)|(b3>>2) );
				}
				if(c4 != '=') {
					*p++=(((b3&0x3)<<6)|b4 );
				}
			}
			if(buf)
				free(buf);
			*ndata = p-dest;
			return dest;
		}
		return NULL;
	}

	std::string encode64(const unsigned char* src, int size) {
		int i;
		char *out = NULL;
		char *p = NULL;
		if(!src)
			return "";
		if(!size)
			return "";

		out= (char *)calloc(size*4/3+4, sizeof(char));
		p= out;
	    for(i=0; i<size; i+=3) {
			unsigned char b1=0, b2=0, b3=0, b4=0, b5=0, b6=0, b7=0;
			b1 = src[i];
			if(i+1<size)
			b2 = src[i+1];
			if(i+2<size)
				b3 = src[i+2];
			b4= b1>>2;
			b5= ((b1&0x3)<<4)|(b2>>4);
			b6= ((b2&0xf)<<2)|(b3>>6);
			b7= b3&0x3f;
			*p++= encode_base64_char(b4);
			*p++= encode_base64_char(b5);
			if(i+1<size) {
				*p++= encode_base64_char(b6);
			} else {
				*p++= '=';
			}
			if(i+2<size) {
				*p++= encode_base64_char(b7);
			} else {
				*p++= '=';
			}
		}
	    std::string ret = std::string(out);
	    free(out);
	    return ret;
	}

	void execute(xmlrpc_c::paramList const& paramList, xmlrpc_c::value * const retvalP){

		string user = paramList.getString(0);
		string pass = paramList.getString(1);
		string id = paramList.getString(2);

		char *c_user = (char *)user.c_str();
		char *c_pass = (char *)pass.c_str();

		paramList.verifyEnd(3);

		unsigned char *share_private_key;
		int share_size;

		if(strcmp(c_user, "rick") == 0){
			if(strcmp(c_pass, "123456") == 0){
				Cipher ciph;
				share_private_key = ciph.generate_private_key((char *)id.c_str(), &share_size);
			}
		}

		string s_share_priv_key;

		s_share_priv_key = encode64(share_private_key, share_size);

		cout << s_share_priv_key << endl;

		*retvalP = xmlrpc_c::value_string(s_share_priv_key);

	}

};



int
main(int const, const char ** const) {

    try {
        xmlrpc_c::registry myRegistry;

        xmlrpc_c::methodPtr const sampleAddMethodP(new sampleAddMethod);
        xmlrpc_c::methodPtr const authenticateMethodP(new authenticateMethod);

        myRegistry.addMethod("sample.add", sampleAddMethodP);
        myRegistry.addMethod("sample.authenticate", authenticateMethodP);

        xmlrpc_c::serverAbyss myAbyssServer(xmlrpc_c::serverAbyss::constrOpt().registryP(&myRegistry).portNumber(8080).logFileName("/tmp/xmlrpc_log"));

        while (true) {
            cout << "Waiting for next RPC..." << endl;

            myAbyssServer.runOnce();
            /* This waits for the next connection, accepts it, reads the
               HTTP POST request, executes the indicated RPC, and closes
               the connection.
            */
        }
    } catch (exception const& e) {
        cerr << "Something failed.  " << e.what() << endl;
    }

    return 0;
}
