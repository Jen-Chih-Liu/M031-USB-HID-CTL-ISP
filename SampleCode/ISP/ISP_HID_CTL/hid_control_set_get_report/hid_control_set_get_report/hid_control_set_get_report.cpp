// hid_control_set_get_report.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS  
#include <iostream>
#include <windows.h>
#include <time.h>
extern "C" {

	// This file is in the Windows DDK available from Microsoft.
#include "hidsdi.h"

#include "setupapi.h"
#include <dbt.h>
}
//#define dbg_printf printf
#define dbg_printf(...) 
HIDP_CAPS							Capabilities;
PSP_DEVICE_INTERFACE_DETAIL_DATA	detailData;
HANDLE								DeviceHandle;
DWORD								dwError;
HANDLE								hEventObject;
HANDLE								hDevInfo;
GUID								HidGuid;
OVERLAPPED							HIDOverlapped;
char								InputReport[256];
ULONG								Length;
LPOVERLAPPED						lpOverLap;
bool								MyDeviceDetected = FALSE;
DWORD								NumberOfBytesRead;
char								OutputReport[256];
HANDLE								ReadHandle;
ULONG								Required;
HANDLE								WriteHandle;

unsigned char W_APROM_BUFFER[128 * 1024];
unsigned int file_size;
unsigned int file_checksum;

int VendorID = 0x0416;
int ProductID = 0x5020;
typedef enum {	
	RES_PASS=0,
	RES_FALSE,
	RES_FILE_NO_FOUND,
	RES_PROGRAM_FALSE,
	RES_CONNECT_FALSE,
	RES_DISCONNECT,
	RES_FILE_SIZE_OVER,
	RES_TIME_OUT,
	RES_NO_DETECT,
	RES_USB_WRITE_FALSE,
	RES_USB_READ_FALSE,	
} ISP_STATE;
ISP_STATE ConnectHID(void)
{
	//Use a series of API calls to find a HID with a specified Vendor IF and Product ID.

	HIDD_ATTRIBUTES						Attributes;
	DWORD								DeviceUsage;
	SP_DEVICE_INTERFACE_DATA			devInfoData;
	bool								LastDevice = FALSE;
	int									MemberIndex = 0;
	LONG								Result;


	Length = 0;
	detailData = NULL;
	DeviceHandle = NULL;

	/*
	API function: HidD_GetHidGuid
	Get the GUID for all system HIDs.
	Returns: the GUID in HidGuid.
	*/

	HidD_GetHidGuid(&HidGuid);

	/*
	API function: SetupDiGetClassDevs
	Returns: a handle to a device information set for all installed devices.
	Requires: the GUID returned by GetHidGuid.
	*/

	hDevInfo = SetupDiGetClassDevs
	(&HidGuid,
		NULL,
		NULL,
		DIGCF_PRESENT | DIGCF_INTERFACEDEVICE);

	devInfoData.cbSize = sizeof(devInfoData);

	//Step through the available devices looking for the one we want. 
	//Quit on detecting the desired device or checking all available devices without success.

	MemberIndex = 0;
	LastDevice = FALSE;

	do
	{
		/*
		API function: SetupDiEnumDeviceInterfaces
		On return, MyDeviceInterfaceData contains the handle to a
		SP_DEVICE_INTERFACE_DATA structure for a detected device.
		Requires:
		The DeviceInfoSet returned in SetupDiGetClassDevs.
		The HidGuid returned in GetHidGuid.
		An index to specify a device.
		*/

		Result = SetupDiEnumDeviceInterfaces
		(hDevInfo,
			0,
			&HidGuid,
			MemberIndex,
			&devInfoData);

		if (Result != 0)
		{
			//A device has been detected, so get more information about it.

			/*
			API function: SetupDiGetDeviceInterfaceDetail
			Returns: an SP_DEVICE_INTERFACE_DETAIL_DATA structure
			containing information about a device.
			To retrieve the information, call this function twice.
			The first time returns the size of the structure in Length.
			The second time returns a pointer to the data in DeviceInfoSet.
			Requires:
			A DeviceInfoSet returned by SetupDiGetClassDevs
			The SP_DEVICE_INTERFACE_DATA structure returned by SetupDiEnumDeviceInterfaces.

			The final parameter is an optional pointer to an SP_DEV_INFO_DATA structure.
			This application doesn't retrieve or use the structure.
			If retrieving the structure, set
			MyDeviceInfoData.cbSize = length of MyDeviceInfoData.
			and pass the structure's address.
			*/

			//Get the Length value.
			//The call will return with a "buffer too small" error which can be ignored.

			Result = SetupDiGetDeviceInterfaceDetail
			(hDevInfo,
				&devInfoData,
				NULL,
				0,
				&Length,
				NULL);

			//Allocate memory for the hDevInfo structure, using the returned Length.

			detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(Length);

			//Set cbSize in the detailData structure.

			detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

			//Call the function again, this time passing it the returned buffer size.

			Result = SetupDiGetDeviceInterfaceDetail
			(hDevInfo,
				&devInfoData,
				detailData,
				Length,
				&Required,
				NULL);

			// Open a handle to the device.
			// To enable retrieving information about a system mouse or keyboard,
			// don't request Read or Write access for this handle.

			/*
			API function: CreateFile
			Returns: a handle that enables reading and writing to the device.
			Requires:
			The DevicePath in the detailData structure
			returned by SetupDiGetDeviceInterfaceDetail.
			*/

			DeviceHandle = CreateFile
			(detailData->DevicePath,
				0,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				(LPSECURITY_ATTRIBUTES)NULL,
				OPEN_EXISTING,
				0,
				NULL);

			/*
			API function: HidD_GetAttributes
			Requests information from the device.
			Requires: the handle returned by CreateFile.
			Returns: a HIDD_ATTRIBUTES structure containing
			the Vendor ID, Product ID, and Product Version Number.
			Use this information to decide if the detected device is
			the one we're looking for.
			*/

			//Set the Size to the number of bytes in the structure.

			Attributes.Size = sizeof(Attributes);

			Result = HidD_GetAttributes
			(DeviceHandle,
				&Attributes);

			//Is it the desired device?

			MyDeviceDetected = FALSE;

			if (Attributes.VendorID == VendorID)
			{
				if (Attributes.ProductID == ProductID)
				{
					//Both the Vendor ID and Product ID match.

					MyDeviceDetected = TRUE;
					//MyDevicePathName = detailData->DevicePath;
					//printf("Device detected");

					//Register to receive device notifications.

					//RegisterForDeviceNotifications();

					//Get the device's capablities.

					//Get the Capabilities structure for the device.
					PHIDP_PREPARSED_DATA	PreparsedData;

					/*
					API function: HidD_GetPreparsedData
					Returns: a pointer to a buffer containing the information about the device's capabilities.
					Requires: A handle returned by CreateFile.
					There's no need to access the buffer directly,
					but HidP_GetCaps and other API functions require a pointer to the buffer.
					*/

					HidD_GetPreparsedData(DeviceHandle, &PreparsedData);

					/*
					API function: HidP_GetCaps
					Learn the device's capabilities.
					For standard devices such as joysticks, you can find out the specific
					capabilities of the device.
					For a custom device, the software will probably know what the device is capable of,
					and the call only verifies the information.
					Requires: the pointer to the buffer returned by HidD_GetPreparsedData.
					Returns: a Capabilities structure containing the information.
					*/

					HidP_GetCaps(PreparsedData, &Capabilities);
					HidD_FreePreparsedData(PreparsedData);

					// 利用HID Report Descriptor來辨識HID Transfer裝置   
					DeviceUsage = (Capabilities.UsagePage * 256) + Capabilities.Usage;

					if (DeviceUsage != 0xFF0001)   // Report Descriptor
						continue;

					// Get a handle for writing Output reports.
					WriteHandle = CreateFile
					(detailData->DevicePath,
						GENERIC_WRITE,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						(LPSECURITY_ATTRIBUTES)NULL,
						OPEN_EXISTING,
						0,
						NULL);

					// Prepare to read reports using Overlapped I/O.

					//PrepareForOverlappedTransfer();
					
						//Get a handle to the device for the overlapped ReadFiles.

						ReadHandle = CreateFile
						(detailData->DevicePath,
							GENERIC_READ,
							FILE_SHARE_READ | FILE_SHARE_WRITE,
							(LPSECURITY_ATTRIBUTES)NULL,
							OPEN_EXISTING,
							FILE_FLAG_OVERLAPPED,
							NULL);


						//Get an event object for the overlapped structure.

						/*API function: CreateEvent
						Requires:
						  Security attributes or Null
						  Manual reset (true). Use ResetEvent to set the event object's state to non-signaled.
						  Initial state (true = signaled)
						  Event object name (optional)
						Returns: a handle to the event object
						*/

						if (hEventObject == 0)
						{
							hEventObject = CreateEvent(NULL,TRUE,TRUE,"");

							//Set the members of the overlapped structure.
							HIDOverlapped.hEvent = hEventObject;
							HIDOverlapped.Offset = 0;
							HIDOverlapped.OffsetHigh = 0;
						}

				} //if (Attributes.ProductID == ProductID)

				else
					//The Product ID doesn't match.

					CloseHandle(DeviceHandle);

			} //if (Attributes.VendorID == VendorID)

			else
				//The Vendor ID doesn't match.

				CloseHandle(DeviceHandle);

			//Free the memory used by the detailData structure (no longer needed).

			free(detailData);

		}  //if (Result != 0)

		else
			//SetupDiEnumDeviceInterfaces returned 0, so there are no more devices to check.
			LastDevice = TRUE;

		//If we haven't found the device yet, and haven't tried every available device,
		//try the next one.

		MemberIndex = MemberIndex + 1;

	} //do

	while ((LastDevice == FALSE) && (MyDeviceDetected == FALSE));

	if (MyDeviceDetected == FALSE)
		printf("Device not detected\n\r");
	else
		printf("Device detected\n\r");

	//Free the memory reserved for hDevInfo by SetupDiClassDevs.
	SetupDiDestroyDeviceInfoList(hDevInfo);
	
	if (MyDeviceDetected == FALSE)
		return RES_PASS;
	else
		return RES_NO_DETECT;
}

void CloseHandles(void )
{
	//Close open handles.

	if (DeviceHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(DeviceHandle);
	}

	if (ReadHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(ReadHandle);
	}

	if (WriteHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(WriteHandle);
	}
}
#if 0
void WriteOutputReport(void)
{
	//Send a report to the device.

	DWORD	BytesWritten = 0;
	INT		Index = 0;
	ULONG	Result;
	
	INT BufSize = 0;

	for (int i = 1; i < 65; i++)
		OutputReport[i] = i; //array 1 to  64
	BufSize = 65;

	//Send a report to the device.

	/*
	HidD_SetOutputReport
	Sends a report to the device.
	Returns: success or failure.
	Requires:
	The device handle returned by CreateFile.
	A buffer that holds the report.
	The Output Report length returned by HidP_GetCaps,
	*/

	if (WriteHandle != INVALID_HANDLE_VALUE)
	{
		Result = HidD_SetOutputReport
		(WriteHandle,
			OutputReport,
			Capabilities.OutputReportByteLength);
	}

	if (Result)
	{
		printf("An Output report was written to the device.\n\r");
	}
	else
	{
		//The write attempt failed, so close the handles, display a message,
		//and set MyDeviceDetected to FALSE so the next attempt will look for the device.
		CloseHandles();
	}
}


void ReadInputReport(void)
{

	// Retrieve an Input report from the device.

	DWORD	Result;


	//Read a report from the device using a control transfer.

	/*
	HidD_GetInputReport
	Returns:
	True on success
	Requires:
	A device handle returned by CreateFile.
	A buffer to hold the report.
	The report length returned by HidP_GetCaps in Capabilities.InputReportByteLength.
	*/

	if (ReadHandle != INVALID_HANDLE_VALUE)
	{
		Result = HidD_GetInputReport
		(ReadHandle,
			InputReport,
			Capabilities.InputReportByteLength);
	}
	else
	{
		Result = FALSE;
	}

	if (!Result)
	{
		//The read attempt failed, so close the handles, display a message,
		//and set MyDeviceDetected to FALSE so the next attempt will look for the device.
		CloseHandles();				
	}
	else
	{
		printf("Received Input report:\n\r");

		//Display the report data.
		

	}
}
#endif

ISP_STATE WriteOutputReport(unsigned char *pcBuffer)
{
	//Send a report to the device.

	DWORD	BytesWritten = 0;
	INT		Index = 0;
	ULONG	Result;

	INT BufSize = 0;

	memcpy(OutputReport + 1, pcBuffer, 64);
	OutputReport[0] = 0;//FIRST BYTE ALWAY IS 0
	BufSize = 65;

	//Send a report to the device.

	/*
	HidD_SetOutputReport
	Sends a report to the device.
	Returns: success or failure.
	Requires:
	The device handle returned by CreateFile.
	A buffer that holds the report.
	The Output Report length returned by HidP_GetCaps,
	*/

	if (WriteHandle != INVALID_HANDLE_VALUE)
	{
		Result = HidD_SetOutputReport
		(WriteHandle,
			OutputReport,
			Capabilities.OutputReportByteLength);
	}

	if (Result)
	{
		//printf("An Output report was written to the device.\n\r");
		return RES_PASS;
	}
	else
	{
		//The write attempt failed, so close the handles, display a message,
		//and set MyDeviceDetected to FALSE so the next attempt will look for the device.
		CloseHandles();
		return RES_USB_WRITE_FALSE;
	}
}


ISP_STATE ReadInputReport(unsigned char *pcBuffer)
{

	// Retrieve an Input report from the device.

	DWORD	Result;


	//Read a report from the device using a control transfer.

	/*
	HidD_GetInputReport
	Returns:
	True on success
	Requires:
	A device handle returned by CreateFile.
	A buffer to hold the report.
	The report length returned by HidP_GetCaps in Capabilities.InputReportByteLength.
	*/

	if (ReadHandle != INVALID_HANDLE_VALUE)
	{
		Result = HidD_GetInputReport
		(ReadHandle,
			InputReport,
			Capabilities.InputReportByteLength);
	}
	else
	{
		Result = FALSE;
	}

	if (!Result)
	{
		//The read attempt failed, so close the handles, display a message,
		//and set MyDeviceDetected to FALSE so the next attempt will look for the device.
		CloseHandles();
		return RES_USB_READ_FALSE;
	}
	else
	{
		//printf("Received Input report:\n\r");
		//Display the report data.
		memcpy(pcBuffer, InputReport + 1,64);
		return RES_PASS;
	}
}


ISP_STATE File_Open_APROM(char* temp)
{
	FILE *fp;
	file_size = 0;
	if ((fp = fopen(temp, "rb")) == NULL)
	{
		printf("APROM FILE OPEN FALSE\n\r");
		return RES_FILE_NO_FOUND;
	}
	if (fp != NULL)
	{
		while (!feof(fp)) {
			fread(&W_APROM_BUFFER[file_size], sizeof(char), 1, fp);
			file_size++;
		}
	}

	file_size = file_size - 1;
	fclose(fp);

	file_checksum = 0;
	for (unsigned int i = 0; i < file_size; i++)
	{

		file_checksum = file_checksum + W_APROM_BUFFER[i];
	}

	return RES_PASS;
}

#define Package_Size 64
unsigned int PacketNumber;
#define Time_Out_Value 1000
unsigned char buffer[Package_Size] = { 0 };
ISP_STATE SN_PACKAGE_USB(void)
{
	clock_t start_time, end_time;
	float total_time = 0;

	unsigned char cmd[Package_Size] = { 0xa4,0,0,0,
		(PacketNumber & 0xff),((PacketNumber >> 8) & 0xff),((PacketNumber >> 16) & 0xff),((PacketNumber >> 24) & 0xff),
		(PacketNumber & 0xff),((PacketNumber >> 8) & 0xff),((PacketNumber >> 16) & 0xff),((PacketNumber >> 24) & 0xff) };
	if (WriteOutputReport((unsigned char *)&cmd) != RES_PASS)
	{
		return RES_USB_WRITE_FALSE;
	}
	start_time = clock(); /* mircosecond */
	while (1)
	{
		if (ReadInputReport(buffer) != RES_PASS)
		{
			return RES_USB_READ_FALSE;
		}
		dbg_printf("package: 0x%x\n\r", buffer[4]);
		if ((buffer[4] | ((buffer[5] << 8) & 0xff00) | ((buffer[6] << 16) & 0xff0000) | ((buffer[7] << 24) & 0xff000000)) == (PacketNumber + 1))
			break;
		end_time = clock();
		/* CLOCKS_PER_SEC is defined at time.h */
		if ((end_time - start_time) > Time_Out_Value)
			return RES_TIME_OUT;
	}
	PacketNumber += 2;
	return RES_PASS;
}



ISP_STATE READFW_VERSION_USB(void)
{
	clock_t start_time, end_time;
	float total_time = 0;

	unsigned char cmd[Package_Size] = { 0xa6,0,0,0,
		(PacketNumber & 0xff),((PacketNumber >> 8) & 0xff),((PacketNumber >> 16) & 0xff),((PacketNumber >> 24) & 0xff) };
	if (WriteOutputReport((unsigned char *)&cmd) != RES_PASS)
	{
		return RES_USB_WRITE_FALSE;
	}
	start_time = clock(); /* mircosecond */
	while (1)
	{

		if (ReadInputReport(buffer) != RES_PASS)
		{
			return RES_USB_READ_FALSE;
		}
		dbg_printf("package: 0x%x\n\r", buffer[4]);
		if ((buffer[4] | ((buffer[5] << 8) & 0xff00) | ((buffer[6] << 16) & 0xff0000) | ((buffer[7] << 24) & 0xff000000)) == (PacketNumber + 1))
			break;

		end_time = clock();
		/* CLOCKS_PER_SEC is defined at time.h */
		if ((end_time - start_time) > Time_Out_Value)
			return RES_TIME_OUT;

	}
	PacketNumber += 2;
	printf("fw version:0x%x\n\r", (buffer[8] | ((buffer[9] << 8) & 0xff00) | ((buffer[10] << 16) & 0xff0000) | ((buffer[11] << 24) & 0xff000000)));
	return RES_PASS;
}

ISP_STATE READ_PID_USB(void)
{
	clock_t start_time, end_time;
	float total_time = 0;
	unsigned char cmd[Package_Size] = { 0xB1,0,0,0,
		(PacketNumber & 0xff),((PacketNumber >> 8) & 0xff),((PacketNumber >> 16) & 0xff),((PacketNumber >> 24) & 0xff) };
	if (WriteOutputReport((unsigned char *)&cmd) != RES_PASS)
	{
		return RES_USB_WRITE_FALSE;
	}
	start_time = clock(); /* mircosecond */
	while (1)
	{
		if (ReadInputReport(buffer) != RES_PASS)
		{
			return RES_USB_READ_FALSE;
		}
		dbg_printf("package: 0x%x\n\r", buffer[4]);
		if ((buffer[4] | ((buffer[5] << 8) & 0xff00) | ((buffer[6] << 16) & 0xff0000) | ((buffer[7] << 24) & 0xff000000)) == (PacketNumber + 1))
			break;

		end_time = clock();
		/* CLOCKS_PER_SEC is defined at time.h */
		if ((end_time - start_time) > Time_Out_Value)
			return RES_TIME_OUT;
	}
	dbg_printf("pid: 0x%x\n\r", (buffer[8] | ((buffer[9] << 8) & 0xff00) | ((buffer[10] << 16) & 0xff0000) | ((buffer[11] << 24) & 0xff000000)));
	dbg_printf("\n\r");
	PacketNumber += 2;
	
	unsigned int temp_PDID = buffer[8] | ((buffer[9] << 8) & 0xff00) | ((buffer[10] << 16) & 0xff0000) | ((buffer[11] << 24) & 0xff000000);
	printf("Pid=x%x\n\r", temp_PDID);
	return RES_PASS;
}



ISP_STATE READ_CONFIG_USB(void)
{
	clock_t start_time, end_time;
	float total_time = 0;

	unsigned char cmd[Package_Size] = { 0xa2,0, 0, 0,
		(PacketNumber & 0xff),((PacketNumber >> 8) & 0xff),((PacketNumber >> 16) & 0xff),((PacketNumber >> 24) & 0xff) };
	if (WriteOutputReport((unsigned char *)&cmd) != RES_PASS)
	{
		return RES_USB_WRITE_FALSE;
	}
	start_time = clock(); /* mircosecond */
	while (1)
	{
		if (ReadInputReport(buffer) != RES_PASS)
		{
			return RES_USB_READ_FALSE;
		}
		dbg_printf("package: 0x%x\n\r", buffer[4]);
		if ((buffer[4] | ((buffer[5] << 8) & 0xff00) | ((buffer[6] << 16) & 0xff0000) | ((buffer[7] << 24) & 0xff000000)) == (PacketNumber + 1))
			break;
		end_time = clock();
		/* CLOCKS_PER_SEC is defined at time.h */
		if ((end_time - start_time) > Time_Out_Value)
		{
			return RES_TIME_OUT;
		}
	}
	printf("config0: 0x%x\n\r", (buffer[8] | ((buffer[9] << 8) & 0xff00) | ((buffer[10] << 16) & 0xff0000) | ((buffer[11] << 24) & 0xff000000)));
	printf("config1: 0x%x\n\r", (buffer[12] | ((buffer[13] << 8) & 0xff00) | ((buffer[14] << 16) & 0xff0000) | ((buffer[15] << 24) & 0xff000000)));
	printf("config2: 0x%x\n\r", (buffer[16] | ((buffer[17] << 8) & 0xff00) | ((buffer[18] << 16) & 0xff0000) | ((buffer[19] << 24) & 0xff000000)));
	printf("\n\r");
	PacketNumber += 2;
	return RES_PASS;
}


ISP_STATE UPDATED_CONFIG(unsigned int config0,unsigned int config1, unsigned  int config2)
{
	clock_t start_time, end_time;
	float total_time = 0;

	unsigned char cmd[Package_Size] = { 0xa1,0, 0, 0,
		(PacketNumber & 0xff),((PacketNumber >> 8) & 0xff),((PacketNumber >> 16) & 0xff),((PacketNumber >> 24) & 0xff), 
	    (config0 & 0xff),((config0 >> 8) & 0xff),((config0 >> 16) & 0xff),((config0 >> 24) & 0xff),
		(config1 & 0xff),((config1 >> 8) & 0xff),((config1 >> 16) & 0xff),((config1 >> 24) & 0xff),
		(config2 & 0xff),((config2 >> 8) & 0xff),((config2 >> 16) & 0xff),((config2 >> 24) & 0xff)
	};

	if (WriteOutputReport((unsigned char *)&cmd) != RES_PASS)
	{
		return RES_USB_WRITE_FALSE;
	}
	start_time = clock(); /* mircosecond */
	while (1)
	{
		if (ReadInputReport(buffer) != RES_PASS)
		{
			return RES_USB_READ_FALSE;
		}
		dbg_printf("package: 0x%x\n\r", buffer[4]);
		if ((buffer[4] | ((buffer[5] << 8) & 0xff00) | ((buffer[6] << 16) & 0xff0000) | ((buffer[7] << 24) & 0xff000000)) == (PacketNumber + 1))
			break;
		end_time = clock();
		/* CLOCKS_PER_SEC is defined at time.h */
		if ((end_time - start_time) > Time_Out_Value)
		{
			return RES_TIME_OUT;
		}
	}
	//printf("new config0: 0x%x\n\r", (buffer[8] | ((buffer[9] << 8) & 0xff00) | ((buffer[10] << 16) & 0xff0000) | ((buffer[11] << 24) & 0xff000000)));
	//printf("new config1: 0x%x\n\r", (buffer[12] | ((buffer[13] << 8) & 0xff00) | ((buffer[14] << 16) & 0xff0000) | ((buffer[15] << 24) & 0xff000000)));
	//printf("new config2: 0x%x\n\r", (buffer[14] | ((buffer[17] << 8) & 0xff00) | ((buffer[18] << 16) & 0xff0000) | ((buffer[19] << 24) & 0xff000000)));	
	PacketNumber += 2;
	return RES_PASS;
}


ISP_STATE RUN_TO_APROM_USB(void)
{
	unsigned char cmd[Package_Size] = { 0xab,0,0,0,
		(PacketNumber & 0xff),((PacketNumber >> 8) & 0xff),((PacketNumber >> 16) & 0xff),((PacketNumber >> 24) & 0xff) };
	if (WriteOutputReport((unsigned char *)&cmd) != RES_PASS)
	{
		return RES_USB_WRITE_FALSE;
	}
	PacketNumber += 2;
	return RES_PASS;
}



ISP_STATE RUN_TO_LDROM_USB(void)
{
	unsigned char cmd[Package_Size] = { 0xac,0,0,0,
		(PacketNumber & 0xff),((PacketNumber >> 8) & 0xff),((PacketNumber >> 16) & 0xff),((PacketNumber >> 24) & 0xff) };
	if (WriteOutputReport((unsigned char *)&cmd) != RES_PASS)
	{
		return RES_USB_WRITE_FALSE;
	}
	PacketNumber += 2;
	return RES_PASS;
}

ISP_STATE RUN_TO_RESET_USB(void)
{
	unsigned char cmd[Package_Size] = { 0xad,0,0,0,
		(PacketNumber & 0xff),((PacketNumber >> 8) & 0xff),((PacketNumber >> 16) & 0xff),((PacketNumber >> 24) & 0xff) };
	if (WriteOutputReport((unsigned char *)&cmd) != RES_PASS)
	{
		return RES_USB_WRITE_FALSE;
	}
	PacketNumber += 2;
	return RES_PASS;
}
unsigned char send_buf[64];
#define CMD_UPDATE_APROM	0x000000A0
void WordsCpy(void *dest, void *src, unsigned int size)
{
	unsigned char *pu8Src, *pu8Dest;
	unsigned int i;

	pu8Dest = (unsigned char *)dest;
	pu8Src = (unsigned char *)src;

	for (i = 0; i < size; i++)
		pu8Dest[i] = pu8Src[i];
}
ISP_STATE UPDATE_APROM_USB(void)
{
	clock_t start_time, end_time;
	float total_time = 0;
	unsigned int count = 0;
	unsigned long cmdData = 0, startaddr = 0;
	memset(send_buf, 0, Package_Size);
	cmdData = CMD_UPDATE_APROM;//CMD_UPDATE_APROM
	WordsCpy(send_buf + 0, &cmdData, 4);
	WordsCpy(send_buf + 4, &PacketNumber, 4);
	startaddr = 0;
	WordsCpy(send_buf + 8, &startaddr, 4);
	WordsCpy(send_buf + 12, &file_size, 4);
	WordsCpy(send_buf + 16, W_APROM_BUFFER + 0, 48);
	if (WriteOutputReport((unsigned char *)&send_buf) != RES_PASS)
	{
		return RES_USB_WRITE_FALSE;
	}
	start_time = clock(); /* mircosecond */
	printf("Waiting chip erase...\n\r");
	//SLEEP 3 SEC
	Sleep(3000);
	while (1)
	{
		if (ReadInputReport(buffer) != RES_PASS)
		{
			return RES_USB_READ_FALSE;
		}
		dbg_printf("package: 0x%x\n\r", buffer[4]);
		if ((buffer[4] | ((buffer[5] << 8) & 0xff00) | ((buffer[6] << 16) & 0xff0000) | ((buffer[7] << 24) & 0xff000000)) == (PacketNumber + 1))
			break;
		end_time = clock();
		//if ((end_time - start_time) > Time_Out_Value)
		//{
		//	printf("Time out\n\r");
		//	return RES_TIME_OUT;
		//}

	}
	PacketNumber = PacketNumber + 2;
	printf("erase down\n\r");
	for (unsigned int i = 48; i < file_size; i = i + 56)
	{


		printf("Process=%.2f %%\r", (float)((float)i / (float)file_size) * 100);

		//clear buffer
		for (unsigned int j = 0; j < 64; j++)
		{
			send_buf[j] = 0;
		}

		WordsCpy(send_buf + 4, &PacketNumber, 4);
		if ((file_size - i) > 56)
		{
			WordsCpy(send_buf + 8, W_APROM_BUFFER + i, 56);
			//read check  package
			if (WriteOutputReport((unsigned char *)&send_buf) != RES_PASS)
			{
				return RES_USB_WRITE_FALSE;
			}
			//sleep 50ms for programming
			Sleep(50);
			while (1)
			{
			
				if (ReadInputReport(buffer) != RES_PASS)
				{
					return RES_USB_READ_FALSE;
				}
				dbg_printf("package: 0x%x\n\r", buffer[4]);
				if ((buffer[4] | ((buffer[5] << 8) & 0xff00) | ((buffer[6] << 16) & 0xff0000) | ((buffer[7] << 24) & 0xff000000)) == (PacketNumber + 1))
				{

					break;
				}
				else
				{

					printf("error\n\r");
					return RES_FALSE;
				}
			}
		}
		else
		{


			WordsCpy(send_buf + 8, W_APROM_BUFFER + i, file_size - i);
			if (WriteOutputReport((unsigned char *)&send_buf) != RES_PASS)
			{
				return RES_USB_WRITE_FALSE;
			}
			//sleep for programming
			Sleep(50);
			while (1)
			{
		

				if (ReadInputReport(buffer) != RES_PASS)
				{
					return RES_USB_READ_FALSE;
				}
				dbg_printf("package: 0x%x\n\r", buffer[4]);
				if ((buffer[4] | ((buffer[5] << 8) & 0xff00) | ((buffer[6] << 16) & 0xff0000) | ((buffer[7] << 24) & 0xff000000)) == (PacketNumber + 1))
				{

					break;
				}
				else
				{

					printf("error\n\r");
					return RES_FALSE;
				}
			}
		}
		PacketNumber = PacketNumber + 2;
	}
	printf("\r                                ");
	printf("\r program progrss: 100%% \n\r");
	return RES_PASS;


}



int main(int argc, char* argv[])
{
#if 0
	ConnectHID();
	WriteOutputReport();
	ReadInputReport();
	CloseHandles();
#endif
	clock_t start_time, end_time;
	float total_time = 0;
	start_time = clock(); /* mircosecond */

	end_time = clock();
	/* CLOCKS_PER_SEC is defined at time.h */
	total_time = (float)(end_time - start_time) / CLOCKS_PER_SEC;
	if (File_Open_APROM(argv[1]) == RES_FILE_NO_FOUND)
	{
		printf("FILE NO FOUND\n\r");
		goto EXIT;
	}
	printf("file:%s\n\r", argv[1]);
	printf("file size:%d\n\r", file_size);
	printf("file checksum:%d\n\r", file_checksum);	
	ConnectHID();
	PacketNumber = 1; //initial package
	SN_PACKAGE_USB();
	READFW_VERSION_USB();
	READ_PID_USB();
	READ_CONFIG_USB();
#if 0 //write config test
	UPDATED_CONFIG(0XFFFFFF7E,0X1FE00,0XFFFFFF5A);
	READ_CONFIG_USB();
#endif
	UPDATE_APROM_USB();
	RUN_TO_APROM_USB();
	
EXIT:
	//CloseHandles();
	end_time = clock();
	/* CLOCKS_PER_SEC is defined at time.h */
	total_time = (float)(end_time - start_time) / CLOCKS_PER_SEC;

	printf("Time : %f sec \n", total_time);
	system("pause");

}
