#include <iostream>  
#include <pthread.h>

using namespace std;  

#define NUM_THREADS 5

int i = 0;

void* say_hello( void* args )  
{  
    cout << i  << "in -here" << endl;
    return NULL;
}

int main()  
{  
    pthread_t tids[NUM_THREADS];
    for(; i < NUM_THREADS; ++i )  
    {  
        cout << i << endl;  
        int ret = pthread_create( &tids[i], NULL, say_hello, NULL );
        if( ret != 0 )
        {
            cout << "pthread_create error:error_code=" << ret << endl;
        }
        cout << i << "---" << endl;
    }
    pthread_exit( NULL );
    return 0;
}  
