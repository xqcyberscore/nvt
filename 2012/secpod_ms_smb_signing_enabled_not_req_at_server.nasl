###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_smb_signing_enabled_not_req_at_server.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft SMB Signing Enabled and Not Required At Server
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "This script finds the SMB Signing is enabled and not required at
  the server.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902798");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-28 10:56:55 +0530 (Tue, 28 Feb 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Microsoft SMB Signing Enabled and Not Required At Server");
  script_xref(name : "URL" , value : "http://mccltd.net/blog/?p=1252");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows");
  script_dependencies("smb_login.nasl");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");

## Variable Initialization
name = "";
port = "";
soc = "";
response = "";
prot = "";

## Get name and port
name = kb_smb_name();
port = kb_smb_transport();

## Open the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

response = smb_session_request(soc:soc, remote:name);
if(!response)
{
  close(soc);
  exit(0);
}

## SMB Negotiate Protocol Response
## If SMB Signing is enabled and not required at the server,
## then Security Mode: 0x07
prot = smb_neg_prot(soc:soc);
if(prot && ord(prot[39]) == 7){
  log_message(data:"SMB Signing is enabled and not required at the server");
}

## Close the socket
close(soc);
