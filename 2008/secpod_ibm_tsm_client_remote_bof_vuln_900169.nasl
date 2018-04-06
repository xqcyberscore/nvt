##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_tsm_client_remote_bof_vuln_900169.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: IBM TSM Client Remote Heap BOF Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

tag_summary = "This host is installed with IBM TSM Client and is prone to heap
  based buffer overflow vulnerability.

  Vulnerability exists due to an input validation error in TSM Backup-Archive
  client, which affects the Client Acceptor Daemon (CAD) and the Backup-Archive
  client scheduler and scheduler service when the option 'SCHEDMODE' is set
  to 'PROMPTED'.";

tag_impact = "Successful exploitation could allow execution of arbitrary code or cause
  denial of service.
  Impact Level: Application";
tag_affected = "- IBM Tivoli Storage Manager (TSM) versions 5.5.0.0 through 5.5.0.7
  - IBM Tivoli Storage Manager (TSM) versions 5.4.0.0 through 5.4.2.2
  - IBM Tivoli Storage Manager (TSM) versions 5.3.0.0 through 5.3.6.1
  - IBM Tivoli Storage Manager (TSM) versions 5.2.0.0 through 5.2.5.2
  - IBM Tivoli Storage Manager (TSM) versions 5.1.0.0 through 5.1.8.1
  - IBM Tivoli Storage Manager (TSM) Express all levels";
tag_solution = "Apply patch
  http://www-01.ibm.com/support/docview.wss?uid=swg21322623";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900169");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-05 06:52:23 +0100 (Wed, 05 Nov 2008)");
  script_cve_id("CVE-2008-4801");
 script_bugtraq_id(31988);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_name("IBM TSM Client Remote Heap BOF Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32465/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-08-071/");

  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\IBM\ADSM\CurrentVersion\Api";
pkgName = registry_get_sz(key:key, item:"Path");

if("Tivoli\TSM" >!< pkgName){
  exit(0);
}

tsmVer = registry_get_sz(key:key, item:"PtfLevel");
if(tsmVer){
  # Grep the versions <= 5.1.8.1, <= 5.2.5.2, <= 5.3.6.1, <= 5.4.2.2, <= 5.5.0.7
  if(egrep(pattern:"^(5\.(1\.([0-7]\..*|8\.[01])|2\.([0-4]\..*|5\.[0-2])|3\." +
                   "([0-5]\..*|6\.[01])|4\.([01]\..*|2\.[0-2])|5\.(0\.[0-7])))$",
           string:tsmVer)){
    security_message(0);
  }
}
