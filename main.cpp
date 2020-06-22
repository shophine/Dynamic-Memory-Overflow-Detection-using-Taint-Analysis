#include "pin.H"

//try
#include <iostream>
#include<vector>
#include<string.h>
#include<string>
#include <cstdio>
#include <sstream>
#include <bits/stdc++.h>
#include <cstring>
#include <algorithm>
#include<stack>

using namespace std;

//

#define MAIN "main"
#define FILENO "fileno"

// Taint the memory if the source of input is stdin
#define FGETS "fgets"
#define GETS "gets"

// Propagate if the src is tainted
#define STRCPY "strcpy@plt"
#define STRNCPY "strncpy@plt"
#define STRCAT "strcat@plt"
#define STRNCAT "strncat@plt"
#define MEMCPY "memcpy@plt"

// Reset tainted memory
#define BZERO "bzero@plt"
#define MEMSET "memset@plt"


//try
struct lookuptable{
	string address;
	int size;
};

struct newLookuptable{
	string address;
	size_t size;
	string stackTrace;
};

struct backtraceTable{
	string addr;
	string funcAddr;
};

stack<string> funcAddrStack;
vector<newLookuptable> funcPrintTable;

vector <lookuptable> table;
//vector <string> taintTable;
vector <backtraceTable> taintTable;

//vector<backtraceTable> backtraceTableVector;

int flag=0;

void addFuncAddrToStack(ADDRINT );
void printNewTaintTable();
string unsignedIntToString(unsigned int );
string addrintToString(ADDRINT );
unsigned int getLastAddress(string ,int );
void generateStackTrace(string , string , string , int );
void removeDuplicate();
int findElementInTable(string );
void printTable();
void printTaintTable();
void addAddressToTaintTable(unsigned int , unsigned int );
unsigned int calculateAddressRange(char *,int );
void printVector(vector<string> );
vector<string> getAddressList(char *,int ,vector<string> );
void addAddressToTable(char* ,int );
string getStack();



void addFuncAddrToStack(ADDRINT funcAddr){
	string funAddrString = addrintToString(funcAddr);
	funcAddrStack.push(funAddrString);
}

void printNewTaintTable(){
	vector<backtraceTable>::iterator it;

	//cout<<"\nprinting the taintTable : "<<endl;

	for(it=taintTable.begin();it!=taintTable.end();it++){
					//cout<<"\nTanited Byte :"<<it->addr<<"\t FuncAddr :"<<it->funcAddr<<endl;
	}
}

string unsignedIntToString(unsigned int x){
	char temp[25];
	sprintf(temp,"0x%x",x);
	//cout<<"(unsignedIntToString) x: "<<temp<<endl;
	string tempString = temp;
	return tempString;

}


string addrintToString(ADDRINT funcAddr){
	char funcAddrHex[25];
	//cout<<"(addrintToString) funcAddrInt : "<<funcAddr<<endl;
	sprintf(funcAddrHex,"0x%x",funcAddr);
	//cout<<"(addrintToString) funcAddrString : "<<funcAddrHex<<endl;
	string funcAddrString = funcAddrHex;
	return funcAddrString;
}


unsigned int getLastAddress(string baseAddrTrim,int sizeofArr){
		//baseAddrTrim.erase(0,2);

    unsigned int baseAddrInt;
    stringstream ss;
    ss << std::hex << baseAddrTrim;
    ss >> baseAddrInt;

		unsigned int offset =  sizeofArr;
		unsigned int lastAddrInt = baseAddrInt + offset - 1;
		//string lastAddrString = unsignedIntToString(lastAddrInt);
		//string baseAddrSting = unsignedIntToString(baseAddrInt);

		return lastAddrInt;
}

void generateStackTrace(string baseAddr, string destAddr, string funcAddr, int destAddrSize){
		cout<<"Inside (generateStackTrace) : "<<baseAddr<<"\t"<<destAddr<<"\t"<<funcAddr<<endl;
		cout<<"Inside (generateStackTrace) : destAddr->size :  "<<destAddrSize<<endl;

		unsigned int baseAddrInt;
		stringstream ss;
		ss << std::hex << destAddr;
		ss >> baseAddrInt;

		unsigned int lastAddrInt = getLastAddress(destAddr,destAddrSize);

		cout<<"Inside (generateStackTrace): baseAddrInt : "<<baseAddrInt<<endl;
		cout<<"Inside (generateStackTrace): lastAddrInt : "<<lastAddrInt<<endl;

		unsigned int i;
		for(i=baseAddrInt;i<=lastAddrInt;i++){\
			cout<<"Inside ForLoop : "<<baseAddr<<"\t"<<unsignedIntToString(i)<<"\t"<<funcAddr<<endl;
			//backtraceTable temp = {baseAddr,unsignedIntToString(i),funcAddr};
			//backtraceTableVector.push_back(temp);
		}


}


void removeDuplicate(){
			//cout<<"\nPIN TOOL : (removeDuplicate)\n";
   		//sort(taintTable.begin(),taintTable.end());

     	//vector<string>::iterator it;

    // it = unique(taintTable.begin(), taintTable.begin() + taintTable.size());

    // taintTable.resize(distance(taintTable.begin(), it));

     //printTaintTable();

 }

 int findElementInTableNew(string key){
 		for(size_t i=0;i<taintTable.size();i++){
 				//cout<<"(findElementInTable): taintTable[i].addr ="<<taintTable[i].addr<<"\tKey : "<<key<<endl;
 				if(taintTable[i].addr==key){
 					return 1;
 				}

 		}
 		return 0;
 }


int findElementInTable(string key){
		for(size_t i=0;i<taintTable.size();i++){
				//cout<<"(findElementInTable): taintTable[i].addr ="<<taintTable[i].addr<<"\tKey : "<<key<<endl;
				if(taintTable[i].addr==key){
					cout<<"[TAINT BYTE]: "<<key<<endl;
					return 1;
				}

		}
		return 0;
}
int findElementInTableForStrcpy(string key, string srcAddrString, string destAddrString){
		for(size_t i=0;i<taintTable.size();i++){
				//cout<<"(findElementInTable): taintTable[i].addr ="<<taintTable[i].addr<<"\tKey : "<<key<<endl;
				if(taintTable[i].addr==key){
					cout<<"[TAINT BYTE]: "<<key<<endl;
					cout<<"[PROPAGATE BYTE]: "<<srcAddrString<<" -> "<<destAddrString<<endl;

					return 1;
				}

		}
		return 0;
}

void printTable()
{
				vector<lookuptable>::iterator it;
				//cout<<"\nPIN TOOL : (printTable)";
				//cout<<"\nTable Size : "<<table.size();
				//cout<<"\nAddr : \t|\tSize Range : \t|\n";
        for(it=table.begin();it!=table.end();it++){
                cout<<it->address<<" |\t"<<it->size<<" |\n";
        }
				cout<<"\n******************************************************************************"<<endl;

}

void printTaintTable()
{
	/*
	removeDuplicate();

	vector<string>::iterator it;
				cout<<"\nPIN TOOL : (printTaintTable)";
				cout<<"\nTaint Table Size : "<<taintTable.size()<<endl;

        for(it=taintTable.begin();it!=taintTable.end();it++){
                cout<<"\t"<<*it<<endl;
        }
				*/


}

void addAddressToTaintTable(unsigned int lowerAddr, unsigned int upperAddr){
	unsigned int i;
	for(i=lowerAddr;i<=upperAddr;i++){
		string dummy = unsignedIntToString(i);
		backtraceTable temp = {dummy,getStack()};
		taintTable.push_back(temp);
	}
}


unsigned int calculateAddressRange(char *str,int sizeofArr){

		char baseAddr[25];
		sprintf(baseAddr,"%p",str);
		//cout<<"(calculateAddressRange): baseaddr : "<<baseAddr<<endl;
		string baseAddrString = baseAddr;
		//baseAddrTrim.erase(0,2);

    unsigned int baseAddrInt;
    stringstream ss;
    ss << std::hex << baseAddrString;
    ss >> baseAddrInt;

		unsigned int offset =  sizeofArr;

		unsigned int lastAddrInt = baseAddrInt + offset - 1;


		return lastAddrInt;

		//string lastAddrString = unsignedIntToString(lastAddrInt);
		//string baseAddrSting = unsignedIntToString(baseAddrInt);

		//addAddressToTaintTable(baseAddrInt,lastAddrInt);
		//removeDuplicate();


}

void printVector(vector<string> v){
				vector<string>::iterator it;

        for(it=v.begin();it!=v.end();it++){
                cout<<"\n"<<*it;
        }
				cout<<endl;
}
vector<string> getAddressList(char *str,int sizeofArr,vector<string> r){


		char baseAddr[25];
		sprintf(baseAddr,"%p",str);

		string baseAddrTrim = baseAddr;
		//baseAddrTrim.erase(0,2);

    unsigned int baseAddrInt;
    stringstream ss;
    ss << std::hex << baseAddrTrim;
    ss >> baseAddrInt;

		unsigned int offset =  sizeofArr;

		unsigned int lastAddrInt = baseAddrInt + offset - 1;

		string lastAddrString = unsignedIntToString(lastAddrInt);
		string baseAddrSting = unsignedIntToString(baseAddrInt);
		unsigned int i;
		cout<<endl;
		for(i=baseAddrInt;i<=lastAddrInt;i++){
			//cout<<"\tIn For Loop: i = "<<i<<"\t Addr to be pushed : "<<unsignedIntToString(i)<<endl;
			r.push_back(unsignedIntToString(i));
		}
		//cout<<"\nAfter For Loop"<<endl;
		printVector(r);
		return r;


}

void addAddressToTable(string baseAddrString,int sizeofArr){
                lookuptable temp = {baseAddrString,sizeofArr};
                table.push_back(temp);

}
void newPrintTable()
{
				cout<<"(newPrintTable)"<<endl;
				vector<newLookuptable>::iterator it;
        for(it=funcPrintTable.begin();it!=funcPrintTable.end();it++){
                cout<<it->address<<" |\t"<<it->size<<" | "<<it->stackTrace<<endl;
        }
				cout<<"\n******************************************************************************"<<endl;

}
string checkInRange(string baseAddrString, size_t size, string key){
	//cout<<"(checkInRange)"<<endl;
	unsigned int baseAddrInt;
	stringstream ss;
	ss << std::hex << baseAddrString;
	ss >> baseAddrInt;

	unsigned int keyInt;
	stringstream ss1;
	ss1 << std::hex << key;
	ss1 >> keyInt;
	size_t t;
	for(t=baseAddrInt;t<=baseAddrInt+size;t++){
		if(keyInt==t){
			return key;
		}
	}
	return baseAddrString;


}
void getStackTraceForAByte(string addrString){
	//newPrintTable();
	//checkPrintableAddrInLookupTable(addrString);
	//cout<<"(getStackTraceForAByte): addrString"<<addrString<<endl;
	vector<newLookuptable>::iterator it;
	int p=0;
	cout<<endl;
	for(it=funcPrintTable.begin();it!=funcPrintTable.end();it++){
					string cir = checkInRange(it->address,it->size,addrString);

					//string ad = it->stackTrace;
				//	cout<<"ad : "<<ad<<endl;
				//	string temp = ad.substr(0,ad.size()-18);
				//	cout<<"temp : "<<temp<<endl;

					cout<<"Stack "<<p++<<": History of Mem("<<cir<<"):"<<it->stackTrace<<endl;
	}

}

string getStack(){
	string funcAddr="";
	vector<string> stackTraceVector;
	for (stack<string> temp = funcAddrStack; !temp.empty(); temp.pop()){
			stackTraceVector.push_back(temp.top());
			//funcAddr+=" <-- ";
			//cout<<"(getStack) : funcAddr"<<funcAddr<<endl;
	}
	stackTraceVector.pop_back();
	vector<string>::iterator it;
    for (it = stackTraceVector.end() - 1; it >= stackTraceVector.begin(); it--){
      funcAddr+=*it;
    	funcAddr+=" ";
}

	return funcAddr;
}

//


typedef int ( *FP_FILENO )(FILE*);
FP_FILENO org_fileno;

INT32 Usage()
{
		return -1;
}

bool isStdin(FILE *fd)
{
		int ret = org_fileno(fd);
		if(ret == 0) return true;
		return false;
}
bool fgets_stdin = false;

VOID fgetsTail(char* ret, ADDRINT funcAddr)
{
		if(fgets_stdin) {
				//addFuncAddrToStack(funcAddr);
				char baseAddrHex[25];
				sprintf(baseAddrHex,"%p",ret);
				string baseAddrString = baseAddrHex;

				addAddressToTable(baseAddrString,strlen(ret));
				newLookuptable temp1 = {baseAddrString,strlen(ret),getStack()};
				funcPrintTable.push_back(temp1);


				unsigned int baseAddrInt, lastAddrInt;
				stringstream ss;
				ss << std::hex << baseAddrString;
				ss >> baseAddrInt;

				//calc lastAddr in unsigned Integer
				lastAddrInt = calculateAddressRange(ret,strlen(ret));

				addAddressToTaintTable(baseAddrInt,lastAddrInt);

					printNewTaintTable();
				//addAddressToTable(ret,strlen(ret)-1);
				//calculateAddressRange(ret,strlen(ret)-1);
		}
		fgets_stdin = false;
}

VOID fgetsHead(char* dest, int size, FILE *stream, ADDRINT funcAddr)
{
		if(isStdin(stream)) {
				fgets_stdin = true;
		}
}

VOID getsTail(char* dest, ADDRINT funcAddr)
{

		//addFuncAddrToStack(funcAddr);
		char baseAddrHex[25];
		sprintf(baseAddrHex,"%p",dest);
		string baseAddrString = baseAddrHex;

		addAddressToTable(baseAddrString,strlen(dest));
		newLookuptable temp1 = {baseAddrString,strlen(dest),getStack()};
		funcPrintTable.push_back(temp1);



		unsigned int baseAddrInt, lastAddrInt;
		stringstream ss;
		ss << std::hex << baseAddrString;
		ss >> baseAddrInt;

		//calc lastAddr in unsigned Integer
		lastAddrInt = calculateAddressRange(dest,strlen(dest));


		addAddressToTaintTable(baseAddrInt,lastAddrInt);

			printNewTaintTable();
		//addAddressToTable(dest,strlen(dest));
    //calculateAddressRange(dest,strlen(dest));

}

VOID mainHead(int argc, char** argv, ADDRINT funcAddr)
{

		addFuncAddrToStack(funcAddr);

		//string funAddrString = addrintToString(funcAddr);
		//funcAddrStack.push(funAddrString);
		int i;
		for(i=1;i<argc;i++){

			unsigned int baseAddrInt, lastAddrInt;

			//calc baseAddr in unsigned Integer
			char baseAddrHex[25];
			sprintf(baseAddrHex,"%p",argv[i]);
			string baseAddrString = baseAddrHex;

			//cout<<"baseAddrString : "<<baseAddrString<<endl;
			//unsigned int baseAddrInt,j;
	    stringstream ss;
	    ss << std::hex << baseAddrString;
	    ss >> baseAddrInt;

			//calc lastAddr in unsigned Integer
			lastAddrInt = calculateAddressRange(argv[i],strlen(argv[i]));
			addAddressToTable(baseAddrString,strlen(argv[i]));

			newLookuptable temp1 = {baseAddrString,strlen(argv[i]),getStack()};
			funcPrintTable.push_back(temp1);

			addAddressToTaintTable(baseAddrInt,lastAddrInt);

			}
		printNewTaintTable();



}



VOID strcpyHead(char* dest, char* src, ADDRINT funcAddr)
{
		//cout<<"\n(In strcpyHead)"<<endl;

		//addFuncAddrToStack(funcAddr);


		//string addrString = addrintToString(funcAddr);
		vector<string> addrList;
		addrList = getAddressList(src,strlen(src),addrList);

		vector<string> destList;

		destList = getAddressList(dest,strlen(src),destList);

		int j=-1;
		//unsigned int i;
		vector<string>::iterator it;
		int flag=0;
		for(it=addrList.begin();it!=addrList.end();it++){
						j++;
						//cout<<"\nval of J : "<<j<<endl;
						//cout<<"(strcpyHead): Key to be searched in table : "<<*it<<endl;
						//
						flag=findElementInTableForStrcpy(*it,addrList[j],destList[j]);
						if(flag==1){

							//
							backtraceTable temp = {destList[j],getStack()};
							//cout<<"printing struct newTaintTable : \taddr: "<<temp.addr<<"\tStackTrace : "<<temp.funcAddr<<endl;
							taintTable.push_back(temp);

							//
						}else{
							//cout<<"No Data Tained!! SAFE\n\n";
						}
		}
					newLookuptable temp1 = {destList[0],strlen(src),getStack()};
					funcPrintTable.push_back(temp1);

						printNewTaintTable();




}
VOID strncpyHead(char* dest, char* src, int n, ADDRINT funcAddr)
{

	//	addFuncAddrToStack(funcAddr);
		vector<string> addrList;
		vector<string> destList;

		addrList = getAddressList(src,n,addrList);
		destList = getAddressList(dest,n,destList);
					int j=-1;
					//unsigned int i;
					vector<string>::iterator it;
					int flag=0;
	        for(it=addrList.begin();it!=addrList.end();it++){
									j++;
									//cout<<"\nval of J : "<<j<<endl;
	                flag=findElementInTableForStrcpy(*it,addrList[j],destList[j]);
									if(flag==1){
											backtraceTable temp = {destList[j],getStack()};
											taintTable.push_back(temp);
										//cout<<"Found Tanied Data, so mark the destination also tained\n";
										//taintTable.push_back(destList[j]);
									}else{
										//cout<<"No Data Tained!! SAFE\n\n";
									}
	        }
					size_t t=n;
					newLookuptable temp1 = {destList[0],t,getStack()};
					funcPrintTable.push_back(temp1);
							printNewTaintTable();

}
VOID strcatHead(char* dest, char* src, ADDRINT funcAddr)
{
		//addFuncAddrToStack(funcAddr);

		//printf("\nstrcatHead: src %p, sizeOfSrc %d\tssizeOfSrc : %d\n", src, strlen(src),strlen(src));
		//printf("\nstrcatHead: dest %p, sizeOfDest %d\tssizeOfDest : %d\n", dest, strlen(dest),strlen(dest));

			vector<string> addrList;
			addrList = getAddressList(src,strlen(src),addrList);
			//printVector(addrList);

			//cout<<"\n\n\nstrcatHead : size of the address list : "<<addrList.size()<<endl;

						vector<string>::iterator it;
						int flag=0;
						//cout<<endl;
						for(it=addrList.begin();it!=addrList.end();it++){
										flag+=findElementInTable(*it);
						}
						if(flag==0){
							//cout<<"No Data Tained!! SAFE\n\n";
						}else{

							//cout<<"Found Tanied Data, so mark the destination also tained\n";
							//cout<<"\n\nSize of Dest : "<<strlen(dest)<<endl;
							unsigned int baseAddrInt, lastAddrInt;

							//calc baseAddr in unsigned Integer
							char baseAddrHex[25];
							sprintf(baseAddrHex,"%p",dest);
							string baseAddrString = baseAddrHex;

							//cout<<"baseAddrString : "<<baseAddrString<<endl;
							//unsigned int baseAddrInt,j;
					    stringstream ss;
					    ss << std::hex << baseAddrString;
					    ss >> baseAddrInt;

							//calc lastAddr in unsigned Integer
							lastAddrInt = calculateAddressRange(dest,strlen(src)+strlen(dest));

							addAddressToTable(baseAddrString,strlen(src)+strlen(dest));

							newLookuptable temp1 = {baseAddrString,strlen(src)+strlen(dest),getStack()};
							funcPrintTable.push_back(temp1);

							addAddressToTaintTable(baseAddrInt,lastAddrInt);



						}
								printNewTaintTable();

}
VOID strncatHead(char* dest, char* src, int n, ADDRINT funcAddr)
{
			//addFuncAddrToStack(funcAddr);
		//printf("\nstrncatHead: src %p, sizeOfSrc %d\tssizeOfSrc : %d\n", src, strlen(src),strlen(src));
		//printf("\nstrncatHead: dest %p, sizeOfDest %d\tssizeOfDest : %d\n", dest, strlen(dest),strlen(dest));
		//printf("\nSize to concatinate from Src to Dest : %d\n",n);
		vector<string> addrList;
		addrList = getAddressList(src,n,addrList);
		//printVector(addrList);

		//cout<<"\n\nstrncatHead : size of the address list : "<<addrList.size()<<endl;

					vector<string>::iterator it;
					int flag=0;
	        for(it=addrList.begin();it!=addrList.end();it++){
	                flag+=findElementInTable(*it);
	        }
					if(flag==0){
						//cout<<"No Data Tained!! SAFE\n\n";
					}else{
						unsigned int baseAddrInt, lastAddrInt;
						//calc baseAddr in unsigned Integer
						char baseAddrHex[25];
						sprintf(baseAddrHex,"%p",dest);
						string baseAddrString = baseAddrHex;

						//cout<<"baseAddrString : "<<baseAddrString<<endl;
						//unsigned int baseAddrInt,j;
						stringstream ss;
						ss << std::hex << baseAddrString;
						ss >> baseAddrInt;

						//calc lastAddr in unsigned Integer
						lastAddrInt = calculateAddressRange(dest,strlen(dest)+n);

						addAddressToTable(baseAddrString,strlen(dest)+n);

						newLookuptable temp1 = {baseAddrString,strlen(dest)+n,getStack()};
						funcPrintTable.push_back(temp1);


						addAddressToTaintTable(baseAddrInt,lastAddrInt);

					}
						printNewTaintTable();
}

VOID memcpyHead(char* dest, char* src, int n, ADDRINT funcAddr)
{
	//addFuncAddrToStack(funcAddr);
	vector<string> addrList;
	vector<string> destList;

	addrList = getAddressList(src,n,addrList);
	destList = getAddressList(dest,n,destList);
	int j=-1;
	//unsigned int i;
	vector<string>::iterator it;
	int flag=0;
	for(it=addrList.begin();it!=addrList.end();it++){
					j++;
					//cout<<"\nval of J : "<<j<<endl;
					flag=findElementInTable(*it);
					if(flag==1){

						backtraceTable temp = {destList[j],getStack()};
						taintTable.push_back(temp);
						//cout<<"Found Tanied Data, so mark the destination also tained\n";

					}else{
						//cout<<"No Data Tained!! SAFE\n\n";
					}
	}

	newLookuptable temp1 = {destList[0],strlen(dest),getStack()};
	funcPrintTable.push_back(temp1);

			printNewTaintTable();


}


VOID bzeroHead(char* src, size_t n, ADDRINT funcAddr)
{
		//addFuncAddrToStack(funcAddr);
		vector<string> addrList;
		addrList = getAddressList(src,n,addrList);
		vector<string>::iterator it;

					int flag=0;
					for(it=addrList.begin();it!=addrList.end();it++){
									flag=findElementInTable(*it);
									if(flag==1){
										cout<<"(bzeroHead): removing the entry"<<endl;

										//erase the entry in taint table
										//add new line

										//taintTable.erase(remove(taintTable.begin(),taintTable.end(),*it),taintTable.end());
									}
					}
			printNewTaintTable();
}

VOID memsetHead(char* src,int c, size_t n, ADDRINT funcAddr)
{
		//addFuncAddrToStack(funcAddr);

		vector<string> addrList;
		addrList = getAddressList(src,n,addrList);
		vector<string>::iterator it;
					int flag=0;
					for(it=addrList.begin();it!=addrList.end();it++){
									flag=findElementInTable(*it);
									if(flag==1){
										//erase the entry in taint table
										//add new line
										cout<<"(memsetHead): removing the entry"<<endl;

										//taintTable.erase(remove(taintTable.begin(),taintTable.end(),*it),taintTable.end());
									}
					}

		printNewTaintTable();
}

VOID retBefore(ADDRINT inst, ADDRINT addr, ADDRINT target)
{
			//printf("retBefore: inst 0x%x, addr 0x%x, target 0x%x\n", inst, addr, target);
			char instHex[25];
			char addrHex[25];
			char targetHex[25];
			sprintf(addrHex,"0x%x",addr);
			string addrString = addrHex;
			sprintf(instHex,"%x",inst);
			sprintf(targetHex,"%x",target);
			//cout<<"(retBefore): funcAddrString: "<<addrString<<endl;
			int flag = findElementInTable(addrString);
			//cout<<"Flag : "<<flag<<endl;
			if (flag){
				cout<<"\n**************************** OVERFLOW DETECTED ******************************\n"<<endl;
				cout<<"Indirect Branch(0x"<<instHex<<"): Jump to 0x"<<targetHex<<", stored in  tainted byte("<<addrHex<<")"<<endl;
				getStackTraceForAByte(addrString);
				//getStack();
				cout<<"\n*****************************************************************************\n"<<endl;
				PIN_ExitProcess(1);
			}else{
			//	cout<<" addr not found in taintTable"<<endl;
			}

}

bool IsAddressInMainExecutable(ADDRINT addr)
{
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(addr);
    PIN_UnlockClient();
    if (rtn == RTN_Invalid())
                    return false;

    SEC sec = RTN_Sec(rtn);
    if (sec == SEC_Invalid())
                    return false;

    IMG img = SEC_Img(sec);
    if (img == IMG_Invalid())
                    return false;
    if(IMG_IsMainExecutable(img)) return true;

    return false;
}

VOID isAFunction(ADDRINT funcAddr){


	if(IsAddressInMainExecutable(funcAddr))
	{
		//cout<<"(isAFunction)"<<endl;
		addFuncAddrToStack(funcAddr);
	}else{
	//	cout<<"(isAFunction) Fail"<<endl;
	}


}

VOID isAReturn(ADDRINT funcAddr,ADDRINT target){

	if(IsAddressInMainExecutable(target))
	{
		//cout<<"(isAReturn)"<<endl;
		funcAddrStack.pop();
	}else{
		//cout<<"(isAReturn) Fail"<<endl;
	}

}

VOID memoryToRegister(ADDRINT funcAddr, UINT32 operandsCount,UINT32 regAddress,ADDRINT memoryAddress,string pointerr){

	string memoryAddressString = addrintToString(memoryAddress);
	string funcAddrString = addrintToString(funcAddr);

	char regAddressHex[25];
	sprintf(regAddressHex,"reg%u",regAddress);
	string regAddressString=regAddressHex;

	int flag = findElementInTableNew(memoryAddressString);
	if(flag==1){
		funcAddrStack.push(funcAddrString);
		//mark reg in taint table
		backtraceTable temp = {regAddressString,getStack()};
		taintTable.push_back(temp);

	}else{
		if(findElementInTableNew(regAddressString)){
			for(size_t i=0;i<taintTable.size();i++){
					//cout<<"(findElementInTable): taintTable[i].addr ="<<taintTable[i].addr<<"\tKey : "<<key<<endl;
					if(taintTable[i].addr==regAddressString){
							taintTable.erase(taintTable.begin()+i,taintTable.begin()+1+i);
							//funcAddrStack.pop();
					}

				}
			}

		}
}
VOID registerToMemory(ADDRINT funcAddr,UINT32 operandsCount, UINT32 regAddress,ADDRINT memoryAddress, string pointerr){

	string memoryAddressString = addrintToString(memoryAddress);
	string funcAddrString = addrintToString(funcAddr);

	char regAddressHex[25];
	sprintf(regAddressHex,"reg%u",regAddress);
	string regAddressString=regAddressHex;

	int flag = findElementInTableNew(regAddressString);
	if(flag==1){
		funcAddrStack.push(funcAddrString);
		//mark reg in taint table
		backtraceTable temp = {memoryAddressString,getStack()};
		taintTable.push_back(temp);

	}else{
		int flag = findElementInTableNew(memoryAddressString);
		if(flag){
			for(size_t i=0;i<taintTable.size();i++){
					//cout<<"(findElementInTable): taintTable[i].addr ="<<taintTable[i].addr<<"\tKey : "<<key<<endl;
					if(taintTable[i].addr==memoryAddressString){
							taintTable.erase(taintTable.begin()+i,taintTable.begin()+1+i);
							//funcAddrStack.pop();
					}

				}
			}

		}
	}




VOID registerToRegister(ADDRINT funcAddr,UINT32 operandsCount,UINT32 reg1Address,UINT32 reg2Address, string pointerr){


		string funcAddrString = addrintToString(funcAddr);

		char reg1AddressHex[25];
		sprintf(reg1AddressHex,"reg%u",reg1Address);
		string reg1AddressString=reg1AddressHex;

		char reg2AddressHex[25];
		sprintf(reg2AddressHex,"reg%u",reg2Address);
		string reg2AddressString=reg2AddressHex;

		int flag = findElementInTableNew(reg1AddressString);
		if(flag==1){
			funcAddrStack.push(funcAddrString);
			//mark reg in taint table
			backtraceTable temp = {reg2AddressString,getStack()};
			taintTable.push_back(temp);

		}else{
			int flag = findElementInTableNew(reg2AddressString);
			if(flag){
				for(size_t i=0;i<taintTable.size();i++){
						//cout<<"(findElementInTable): taintTable[i].addr ="<<taintTable[i].addr<<"\tKey : "<<key<<endl;
						if(taintTable[i].addr==reg2AddressString){
								taintTable.erase(taintTable.begin()+i,taintTable.begin()+1+i);
								//funcAddrStack.pop();
						}

					}
			}

		}
}


VOID returnForRegister(ADDRINT funcAddr,ADDRINT target,UINT32 regAddress){
	string funcAddrString = addrintToString(funcAddr);
	string targetAddrString = addrintToString(target);
	char regAddressHex[25];
	sprintf(regAddressHex,"reg%u",regAddress);
	string regAddressString=regAddressHex;

	int flag = findElementInTableNew(regAddressString);

	if (flag){
		cout<<"\n**************************** OVERFLOW DETECTED ******************************\n"<<endl;
		cout<<"Indirect Branch(0x"<<funcAddr<<"): Jump to 0x"<<target<<", stored in  tainted byte("<<regAddressString<<")"<<endl;
		getStackTraceForAByte(regAddressString);
		//getStack();
		cout<<"\n*****************************************************************************\n"<<endl;

		PIN_ExitProcess(1);
	}else{
	//	cout<<"register not found in taintTable"<<endl;
	}

}

VOID Instruction(INS ins, VOID *v)
{
		if(INS_IsIndirectBranchOrCall(ins)){
				if(INS_IsMemoryRead(ins)) {
						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) retBefore,
								IARG_INST_PTR,
								IARG_MEMORYREAD_EA,
								IARG_BRANCH_TARGET_ADDR,
								IARG_END);
				}
				if (INS_OperandRead(ins, 0) && INS_OperandIsReg(ins,0))
		        {
		            REG reg = INS_OperandReg(ins,0);
		            INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)returnForRegister,
		                IARG_INST_PTR,
		                IARG_BRANCH_TARGET_ADDR,
										IARG_UINT32,reg,
		                IARG_END);
		        }
		}


    if(INS_IsCall(ins))
    {
        RTN rtn = RTN_FindByAddress(INS_Address(ins));

        if (RTN_Valid(rtn))
        {
            INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)isAFunction,
                 IARG_INST_PTR,
                 IARG_END);
        }
    }

    if(INS_IsRet(ins))
    {

        RTN rtn = RTN_FindByAddress(INS_Address(ins));

        if (RTN_Valid(rtn))
        {
            INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)isAReturn,
                 IARG_INST_PTR,
                 IARG_BRANCH_TARGET_ADDR,
                 IARG_END);
        }

    }
		if(INS_OperandCount(ins) > 1 && INS_OperandRead(ins, 1) && INS_OperandWritten(ins,0)){
        if(INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) memoryToRegister,
                           IARG_INST_PTR,
                           IARG_UINT32, INS_OperandCount(ins),
                           IARG_UINT32, INS_OperandReg(ins,0),
                           IARG_MEMORYOP_EA,0,
                           IARG_PTR,new string(INS_Disassemble(ins)),
                           IARG_END);
        }
        else if(INS_MemoryOperandIsWritten(ins, 0) && INS_OperandIsReg(ins, 1)){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) registerToMemory,
                           IARG_INST_PTR,
                           IARG_UINT32,INS_OperandCount(ins),
                           IARG_UINT32, INS_OperandReg(ins,1),
                           IARG_MEMORYOP_EA,0,
                           IARG_PTR,new string(INS_Disassemble(ins)),
                           IARG_END);
        }
        else if(INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) registerToRegister,
                           IARG_INST_PTR,
                           IARG_UINT32, INS_OperandCount(ins),
                           IARG_UINT32, REG(INS_OperandReg(ins,0)),
                           IARG_UINT32, REG(INS_OperandReg(ins,1)),
                           IARG_PTR,new string(INS_Disassemble(ins)),
                           IARG_END);
        }
    }


}

VOID Image(IMG img, VOID *v) {
		RTN rtn;

		rtn = RTN_FindByName(img, FGETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fgetsHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_INST_PTR,
								IARG_END);

				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fgetsTail,
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, GETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getsTail,
								//IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcpyHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}
		rtn = RTN_FindByName(img, STRNCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncpyHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRCAT);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcatHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}
		rtn = RTN_FindByName(img, STRNCAT);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncatHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, MEMCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memcpyHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}

	rtn = RTN_FindByName(img, BZERO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)bzeroHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}
		rtn = RTN_FindByName(img, MEMSET);
			if(RTN_Valid(rtn)) {
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memsetHead,
									IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
									IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
									IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
									IARG_INST_PTR,
									IARG_END);
					RTN_Close(rtn);
			}

		rtn = RTN_FindByName(img, MAIN);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mainHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_INST_PTR,
								IARG_END);
				RTN_Close(rtn);
		}


		rtn = RTN_FindByName(img, FILENO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				AFUNPTR fptr = RTN_Funptr(rtn);
				org_fileno = (FP_FILENO)(fptr);
				RTN_Close(rtn);
		}

}

int main(int argc, char *argv[])
{
  PIN_InitSymbols();

		if(PIN_Init(argc, argv)){
				return Usage();
		}

  IMG_AddInstrumentFunction(Image, 0);
		INS_AddInstrumentFunction(Instruction, 0);
		PIN_StartProgram();

		return 0;
}
