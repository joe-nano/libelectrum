@ECHO OFF
ECHO.
ECHO Downloading libwallet dependencies from NuGet
CALL nuget.exe install ..\vs2013\libwallet\packages.config
ECHO.
CALL buildbase.bat ..\vs2013\libwallet.sln 12
ECHO.
PAUSE