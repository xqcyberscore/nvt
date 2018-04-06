###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ultravnc_mult_int_overflow_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# UltraVNC ClientConnection Multiple Integer Overflow Vulnerabilities (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and may cause remote code execution to compromise
  the affected remote system.

  Impact level: Application/System";

tag_affected = "UltraVNC version prior to 1.0.5.4 on Windows.";
tag_insight = "Multiple Integer Overflow due to signedness errors within the functions
  ClientConnection::CheckBufferSize and ClientConnection::CheckFileZipBufferSize
  in ClientConnection.cpp file fails to validate user input.";
tag_solution = "Upgrade to the latest version 1.0.5.4
  http://www.uvnc.com/download/1054";
tag_summary = "This host is running UltraVNC and is prone to Multiple Integer
  Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900471");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(33568);
  script_cve_id("CVE-2009-0388");
  script_name("UltraVNC ClientConnection Multiple Integer Overflow Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/7990");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33794");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_ultravnc_detect_win.nasl", "find_service1.nasl");
  script_require_ports("Services/vnc", 5800, 5900);
  script_require_keys("UltraVNC/Win/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

vncPort = get_kb_item("Services/vnc");
if(!vncPort){
  vncPort = 5900;
}

if(get_port_state(vncPort))
{
  uvncVer = get_kb_item("UltraVNC/Win/Ver");
  if(!uvncVer){
    exit(0);
  }

  # Grep for UltraVNC version prior to 1.0.5.4
  if(version_is_less(version:uvncVer, test_version:"1.0.5.4")){
    security_message(vncPort);
  }
}
