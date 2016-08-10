
// LuaTCPLink.cpp

// Implements the cLuaTCPLink class representing a Lua wrapper for the cTCPLink class and the callbacks it needs

#include "Globals.h"
#include "LuaTCPLink.h"
#include "LuaServerHandle.h"





cLuaTCPLink::cLuaTCPLink(cPluginLua & a_Plugin, int a_CallbacksTableStackPos):
	m_Plugin(a_Plugin),
	m_Callbacks(cPluginLua::cOperation(a_Plugin)(), a_CallbacksTableStackPos)
{
	// Warn if the callbacks aren't valid:
	if (!m_Callbacks.IsValid())
	{
		LOGWARNING("cTCPLink in plugin %s: callbacks could not be retrieved", m_Plugin.GetName().c_str());
		cPluginLua::cOperation Op(m_Plugin);
		Op().LogStackTrace();
	}
}





cLuaTCPLink::cLuaTCPLink(cPluginLua & a_Plugin, cLuaState::cRef && a_CallbacksTableRef, cLuaServerHandleWPtr a_ServerHandle):
	m_Plugin(a_Plugin),
	m_Callbacks(std::move(a_CallbacksTableRef)),
	m_Server(std::move(a_ServerHandle))
{
	// Warn if the callbacks aren't valid:
	if (!m_Callbacks.IsValid())
	{
		LOGWARNING("cTCPLink in plugin %s: callbacks could not be retrieved", m_Plugin.GetName().c_str());
		cPluginLua::cOperation Op(m_Plugin);
		Op().LogStackTrace();
	}
}





cLuaTCPLink::~cLuaTCPLink()
{
	// If the link is still open, close it:
	cTCPLinkPtr Link = m_Link;
	if (Link != nullptr)
	{
		Link->Close();
	}

	Terminated();
}





bool cLuaTCPLink::Send(const AString & a_Data)
{
	// Safely grab a copy of the link:
	cTCPLinkPtr Link = m_Link;
	if (Link == nullptr)
	{
		return false;
	}

	// Send the data:
	return Link->Send(a_Data);
}





AString cLuaTCPLink::GetLocalIP(void) const
{
	// Safely grab a copy of the link:
	cTCPLinkPtr Link = m_Link;
	if (Link == nullptr)
	{
		return "";
	}

	// Get the IP address:
	return Link->GetLocalIP();
}





UInt16 cLuaTCPLink::GetLocalPort(void) const
{
	// Safely grab a copy of the link:
	cTCPLinkPtr Link = m_Link;
	if (Link == nullptr)
	{
		return 0;
	}

	// Get the port:
	return Link->GetLocalPort();
}





AString cLuaTCPLink::GetRemoteIP(void) const
{
	// Safely grab a copy of the link:
	cTCPLinkPtr Link = m_Link;
	if (Link == nullptr)
	{
		return "";
	}

	// Get the IP address:
	return Link->GetRemoteIP();
}





UInt16 cLuaTCPLink::GetRemotePort(void) const
{
	// Safely grab a copy of the link:
	cTCPLinkPtr Link = m_Link;
	if (Link == nullptr)
	{
		return 0;
	}

	// Get the port:
	return Link->GetRemotePort();
}





void cLuaTCPLink::Shutdown(void)
{
	// Safely grab a copy of the link and shut it down:
	cTCPLinkPtr Link = m_Link;
	if (Link != nullptr)
	{
		Link->Shutdown();
	}
}





void cLuaTCPLink::Close(void)
{
	// If the link is still open, close it:
	cTCPLinkPtr Link = m_Link;
	if (Link != nullptr)
	{
		Link->Close();
	}

	Terminated();
}





AString cLuaTCPLink::StartTLSClient(
	const AString & a_OwnCertData,
	const AString & a_OwnPrivKeyData,
	const AString & a_OwnPrivKeyPassword
)
{
	auto link = m_Link;
	if (link != nullptr)
	{
		cX509CertPtr ownCert;
		if (!a_OwnCertData.empty())
		{
			ownCert = std::make_shared<cX509Cert>();
			auto res = ownCert->Parse(a_OwnCertData.data(), a_OwnCertData.size());
			if (res != 0)
			{
				return Printf("Cannot parse client certificate: -0x%x", res);
			}
		}
		cCryptoKeyPtr ownPrivKey;
		if (!a_OwnPrivKeyData.empty())
		{
			ownPrivKey = std::make_shared<cCryptoKey>();
			auto res = ownPrivKey->ParsePrivate(a_OwnPrivKeyData.data(), a_OwnPrivKeyData.size(), a_OwnPrivKeyPassword);
			if (res != 0)
			{
				return Printf("Cannot parse client private key: -0x%x", res);
			}
		}
		return link->StartTLSClient(ownCert, ownPrivKey);
	}
	return "";
}





AString cLuaTCPLink::StartTLSServer(
	const AString & a_OwnCertData,
	const AString & a_OwnPrivKeyData,
	const AString & a_OwnPrivKeyPassword,
	const AString & a_StartTLSData
)
{
	auto link = m_Link;
	if (link != nullptr)
	{
		// Create the peer cert:
		auto OwnCert = std::make_shared<cX509Cert>();
		int res = OwnCert->Parse(a_OwnCertData.data(), a_OwnCertData.size());
		if (res != 0)
		{
			return Printf("Cannot parse server certificate: -0x%x", res);
		}
		auto OwnPrivKey = std::make_shared<cCryptoKey>();
		res = OwnPrivKey->ParsePrivate(a_OwnPrivKeyData.data(), a_OwnPrivKeyData.size(), a_OwnPrivKeyPassword);
		if (res != 0)
		{
			return Printf("Cannot parse server private key: -0x%x", res);
		}

		return link->StartTLSServer(OwnCert, OwnPrivKey, a_StartTLSData);
	}
	return "";
}





void cLuaTCPLink::Terminated(void)
{
	// Disable the callbacks:
	if (m_Callbacks.IsValid())
	{
		m_Callbacks.UnRef();
	}

	// If the managing server is still alive, let it know we're terminating:
	auto Server = m_Server.lock();
	if (Server != nullptr)
	{
		Server->RemoveLink(this);
	}

	// If the link is still open, close it:
	{
		cTCPLinkPtr Link = m_Link;
		if (Link != nullptr)
		{
			Link->Close();
			m_Link.reset();
		}
	}
}





void cLuaTCPLink::ReceivedCleartextData(const char * a_Data, size_t a_NumBytes)
{
	// Check if we're still valid:
	if (!m_Callbacks.IsValid())
	{
		return;
	}

	// Call the callback:
	cPluginLua::cOperation Op(m_Plugin);
	if (!Op().Call(cLuaState::cTableRef(m_Callbacks, "OnReceivedData"), this, AString(a_Data, a_NumBytes)))
	{
		LOGINFO("cTCPLink OnReceivedData callback failed in plugin %s.", m_Plugin.GetName().c_str());
	}
}





void cLuaTCPLink::OnConnected(cTCPLink & a_Link)
{
	// Check if we're still valid:
	if (!m_Callbacks.IsValid())
	{
		return;
	}

	// Call the callback:
	cPluginLua::cOperation Op(m_Plugin);
	if (!Op().Call(cLuaState::cTableRef(m_Callbacks, "OnConnected"), this))
	{
		LOGINFO("cTCPLink OnConnected() callback failed in plugin %s.", m_Plugin.GetName().c_str());
	}
}





void cLuaTCPLink::OnError(int a_ErrorCode, const AString & a_ErrorMsg)
{
	// Check if we're still valid:
	if (!m_Callbacks.IsValid())
	{
		return;
	}

	// Call the callback:
	cPluginLua::cOperation Op(m_Plugin);
	if (!Op().Call(cLuaState::cTableRef(m_Callbacks, "OnError"), this, a_ErrorCode, a_ErrorMsg))
	{
		LOGINFO("cTCPLink OnError() callback failed in plugin %s; the link error is %d (%s).",
			m_Plugin.GetName().c_str(), a_ErrorCode, a_ErrorMsg.c_str()
		);
	}

	Terminated();
}





void cLuaTCPLink::OnLinkCreated(cTCPLinkPtr a_Link)
{
	// Store the cTCPLink for later use:
	m_Link = a_Link;
}





void cLuaTCPLink::OnReceivedData(const char * a_Data, size_t a_Length)
{
	// Check if we're still valid:
	if (!m_Callbacks.IsValid())
	{
		return;
	}

	// Call the callback:
	cPluginLua::cOperation Op(m_Plugin);
	if (!Op().Call(cLuaState::cTableRef(m_Callbacks, "OnReceivedData"), this, AString(a_Data, a_Length)))
	{
		LOGINFO("cTCPLink OnReceivedData callback failed in plugin %s.", m_Plugin.GetName().c_str());
	}
}





void cLuaTCPLink::OnRemoteClosed(void)
{
	// Check if we're still valid:
	if (!m_Callbacks.IsValid())
	{
		return;
	}

	// Call the callback:
	cPluginLua::cOperation Op(m_Plugin);
	if (!Op().Call(cLuaState::cTableRef(m_Callbacks, "OnRemoteClosed"), this))
	{
		LOGINFO("cTCPLink OnRemoteClosed() callback failed in plugin %s.", m_Plugin.GetName().c_str());
	}

	Terminated();
}





