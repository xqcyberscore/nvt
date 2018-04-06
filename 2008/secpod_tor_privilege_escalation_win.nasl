###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tor_privilege_escalation_win.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# TOR Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the attacker gain privileges and escalate
  the privileges in malicious ways.";
tag_affected = "Tor version 0.2.0.31 or prior.";
tag_insight = "The flaws are due to
  - an application does not properly drop privileges to the primary groups of
    the user specified by the User Parameter.
  - a ClientDNSRejectInternalAddresses configuration option is not always
    enforced which weaknesses the application security.";
tag_solution = "Upgrade to the latest version 0.2.0.32
  http://www.torproject.org/download.html.en";
tag_summary = "This host is installed with TOR and is prone to Privilege
  Escalation vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900423");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5397", "CVE-2008-5398");
  script_bugtraq_id(32648);
  script_name("TOR Privilege Escalation Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://www.torproject.org");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33025");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Privilege escalation");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

torVer = registry_get_sz(item:"DisplayName",
               key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tor");
if(!torVer){
  exit(0);
}

torVer = eregmatch(pattern:"Tor ([0-9.]+)", string:torVer);
if(torVer[1] != NULL)
{
  # Grep for Tor version 0.2.0.31 or prior
  if(version_is_less_equal(version:torVer[1], test_version:"0.2.0.31")){
    security_message(0);
  }
}
