// (c) Copyright Cory Plotts.
// This source is subject to the Microsoft Public License (Ms-PL).
// Please see http://go.microsoft.com/fwlink/?LinkID=131993 for details.
// All other rights reserved.

#include "stdafx.h"

#include "Injector.h"
#include <vcclr.h>

using namespace ManagedInjector;

static unsigned int WM_GOBABYGO = ::RegisterWindowMessage(L"Injector_GOBABYGO!");
static HHOOK MESSAGE_HOOK_HANDLE;

//-----------------------------------------------------------------------------
//Spying Process functions follow
//-----------------------------------------------------------------------------
void Injector::Launch(System::IntPtr windowHandle, System::String^ assembly, System::String^ className, System::String^ methodName)
{
	const auto assemblyClassAndMethod = assembly + "$" + className + "$" + methodName;
	const pin_ptr<const wchar_t> acmLocal = PtrToStringChars(assemblyClassAndMethod);

	HINSTANCE hinstDLL;

	if (::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, LPCTSTR(&MessageHookProc), &hinstDLL))
	{
		LogMessage("GetModuleHandleEx successful.", true);
		DWORD processId = 0;
		const auto threadId = ::GetWindowThreadProcessId(HWND(windowHandle.ToPointer()), &processId);

		if (processId)
		{
			LogMessage("Got process id.", true);
			const auto hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

			if (hProcess)
			{
				LogMessage("Got process handle.", true);

				const int buffLen = (assemblyClassAndMethod->Length + 1) * sizeof(wchar_t);
				auto acmRemote = ::VirtualAllocEx(hProcess, nullptr, buffLen, MEM_COMMIT, PAGE_READWRITE);

				if (acmRemote)
				{
					LogMessage("VirtualAllocEx successful.", true);

					if (::WriteProcessMemory(hProcess, acmRemote, acmLocal, buffLen, nullptr))
					{
						MESSAGE_HOOK_HANDLE = ::SetWindowsHookEx(WH_CALLWNDPROC, &MessageHookProc, hinstDLL, threadId);

						if (MESSAGE_HOOK_HANDLE)
						{
							LogMessage("SetWindowsHookEx successful.", true);

							if (::SendMessage(HWND(windowHandle.ToPointer()), WM_GOBABYGO, WPARAM(acmRemote), 0) == false)
							{
								LogMessage("SendMessage failed.", true);
							}

							if (::UnhookWindowsHookEx(MESSAGE_HOOK_HANDLE) == false)
							{
								LogMessage("UnhookWindowsHookEx failed.", true);
							}
						}
						else
						{
							LogMessage("SetWindowsHookEx failed", true);
						}
					}
					else
					{
						LogMessage("WriteProcessMemory failed.", true);
					}

					if (::VirtualFreeEx(hProcess, acmRemote, 0, MEM_RELEASE) == false)
					{
						LogMessage("VirtualFreeEx failed.", true);
					}
				}

				if (::CloseHandle(hProcess) == false)
				{
					LogMessage("CloseHandle failed.", true);
				}
			}
		}

		if (::FreeLibrary(hinstDLL) == false)
		{
			LogMessage("FreeLibrary failed.", true);
		}
	}
	else
	{
		LogMessage("GetModuleHandleEx failed.", true);
	}
}

void Injector::LogMessage(System::String^ message, const bool append)
{
	auto applicationDataPath = Environment::GetFolderPath(Environment::SpecialFolder::ApplicationData);
	applicationDataPath += "\\Snoop";

	System::IO::Directory::CreateDirectory(applicationDataPath);

	const auto pathname = applicationDataPath + "\\SnoopLog.txt";

	if (!append)
	{
		System::IO::File::Delete(pathname);
	}

	auto fi = gcnew System::IO::FileInfo(pathname);

	auto sw = fi->AppendText();
	sw->WriteLine(System::DateTime::Now.ToString("MM/dd/yyyy HH:mm:ss", System::Globalization::CultureInfo::CurrentCulture) + " : " + message);
	sw->Close();
}

__declspec(dllexport)
LRESULT __stdcall MessageHookProc(const int nCode, const WPARAM wparam, LPARAM lparam)
{
	if (nCode == HC_ACTION)
	{
		const auto msg = reinterpret_cast<CWPSTRUCT*>(lparam);

		if (msg != nullptr
			&& msg->message == WM_GOBABYGO)
		{
			System::Diagnostics::Debug::WriteLine("Got WM_GOBABYGO message");

			const auto acmRemote = reinterpret_cast<wchar_t*>(msg->wParam);

			auto acmLocal = gcnew System::String(acmRemote);
			System::Diagnostics::Debug::WriteLine(System::String::Format("acmLocal = {0}", acmLocal));
			auto acmSplit = acmLocal->Split('$');

			System::Diagnostics::Debug::WriteLine(String::Format("About to load assembly {0}", acmSplit[0]));
			auto assembly = System::Reflection::Assembly::LoadFile(acmSplit[0]);

			if (assembly != nullptr)
			{
				System::Diagnostics::Debug::WriteLine(String::Format("About to load type {0}", acmSplit[1]));
				auto type = assembly->GetType(acmSplit[1]);

				if (type != nullptr)
				{
					System::Diagnostics::Debug::WriteLine(String::Format("Just loaded the type {0}", acmSplit[1]));
					auto methodInfo = type->GetMethod(acmSplit[2], System::Reflection::BindingFlags::Static | System::Reflection::BindingFlags::Public);

					if (methodInfo != nullptr)
					{
						System::Diagnostics::Debug::WriteLine(System::String::Format("About to invoke {0} on type {1}", methodInfo->Name, acmSplit[1]));
						auto returnValue = methodInfo->Invoke(nullptr, nullptr);

						if (nullptr == returnValue)
						{
							returnValue = "NULL";
						}

						System::Diagnostics::Debug::WriteLine(String::Format("Return value of {0} on type {1} is {2}", methodInfo->Name, acmSplit[1], returnValue));
					}
				}
			}
		}
	}

	return CallNextHookEx(MESSAGE_HOOK_HANDLE, nCode, wparam, lparam);
}