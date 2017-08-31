# OpenVAS Vulnerability Test
# $Id: java_jre_jdk_dos.nasl 6456 2017-06-28 11:19:33Z cfischer $
# Description: Sun Java Runtime Environment DoS
#
# Authors:
# William Craig
#
# Copyright:
# Copyright (C) 2004 Netteksecure Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote Windows machine is running a Java SDK or JRE version
 1.4.2_03 and prior which is vulnerable to a DoS attack.";

tag_solution = "Upgrade to SDK and JRE 1.4.2_04
           http://java.sun.com/j2se/";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12244");
  script_version("$Revision: 6456 $");
  script_tag(name:"last_modification", value:"$Date: 2017-06-28 13:19:33 +0200 (Wed, 28 Jun 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0651");
  script_bugtraq_id(10301);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Sun Java Runtime Environment DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Netteksecure Inc.");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

port = get_kb_item("SMB/transport");
if(!port) port = 445;

x_name = kb_smb_name();
if(!x_name)exit(0);

_smb_port = kb_smb_transport();
if(!_smb_port)exit(0);

if(!get_port_state(_smb_port)) exit(0);
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

if(!login)login = "";
if(!pass) pass = "";

          
soc = open_sock_tcp(_smb_port);
if(!soc) exit(0);

#
# Request the session
# 
r = smb_session_request(soc:soc,  remote:x_name);

if(!r) { close(soc); exit(0); }

#
# Negotiate the protocol
#
prot = smb_neg_prot(soc:soc);
if(!prot){ close(soc); exit(0); }


r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
if(!r){ close(soc); exit(0); }

uid = session_extract_uid(reply:r);
if(!uid){ close(soc); exit(0); }

r = smb_tconx(soc:soc, name:x_name, uid:uid, share:"IPC$");
if(!r){ close(soc); exit(0); }

tid = tconx_extract_tid(reply:r);
if(!tid){ close(soc); exit(0); }

r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
if(!r){ close(soc); exit(0);}

pipe = smbntcreatex_extract_pipe(reply:r);
if(!pipe){ close(soc); exit(0);}

r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!r){ close(soc); exit(0); }

handle = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!handle){ close(soc); exit(0); }

key = "SOFTWARE\JavaSoft\Java Runtime Environment";

key_h = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:handle);
if ( key_h )
{
 # Is the remote machine using the JRE?
 item= "CurrentVersion";
 data = registry_get_item_sz(soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:key_h);
 value = registry_decode_sz(data:data, uid:uid);
}

if ( value && ("1.4" >< value) )
{
  entries = registry_enum_key(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:key_h);

  foreach entry (entries)
  {
   if ( ereg(pattern:"^1\.4\.([01]|2_0[0-3])", string:entry) ) 
	  {
	   security_message ( port:port );
	   exit(0);
	  }
  }
}


key = "SOFTWARE\JavaSoft\Java Development Kit";

key_h = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:handle);
if ( key_h )
{
 # Is the remote machine using the JRE?
 item= "CurrentVersion";
 data = registry_get_item_sz(soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:key_h);
 value = registry_decode_sz(data:data, uid:uid);
}

if ( value && ("1.4" >< value) )
{
  entries = registry_enum_key(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:key_h);

  foreach entry (entries)
  {
   if ( ereg(pattern:"^1\.4\.([01]|2_0[0-3])", string:entry) ) 
	  {
	   security_message ( port:port );
	   exit(0);
	  }
  }
}

