##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_pagemaker_mult_bof_vuln_900168.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Adobe PageMaker Font Structure Multiple BOF Vulnerabilities
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

tag_summary = "This host is installed with Adobe PageMaker and is prone to multiple
  buffer overflow vulnerability.

  The flaws are due to error in processing specially crafted PMD files.
  These can be exploited to cause stack-based and heap-based overflow.";

tag_solution = "Apply patch,
  http://www.adobe.com/support/security/advisories/apsa08-10.html

  *****
  NOTE: Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Allows remote attackers to execute arbitrary code, and deny the service.
  Impact Level: Application";
tag_affected = "Adobe PageMaker versions 7.0.2 and prior on Windows (all)";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900168");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-31 14:50:32 +0100 (Fri, 31 Oct 2008)");
  script_bugtraq_id(31975);
  script_cve_id("CVE-2007-6432", "CVE-2007-5394", "CVE-2007-6021");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_name("Adobe PageMaker Font Structure Multiple BOF Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/27200/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/alerts/2008/Oct/1021119.html");

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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Adobe PageMaker 7.0";
pmVer = registry_get_sz(key:key, item:"DisplayVersion");

if(pmVer){
  # Grep for PageMaker versions 7.0.2 and prior
  if(egrep(pattern:"^([0-6](\..*)|7\.0(\.[0-2])?)$", string:pmVer)){
    security_message(0);
  }
}
