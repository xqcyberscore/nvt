###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_wmi_admin_tools_activex_code_exec_vuln.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# Microsoft WMI Administrative Tools ActiveX Control Remote Code Execution Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_impact = "Successful exploitation will let the remote attackers execute arbitrary code
  and can compromise a vulnerable system.
  Impact Level: System";
tag_affected = "Microsoft WMI Administrative Tools 1.1";
tag_insight = "The flaws are due to the 'AddContextRef()' and 'ReleaseContext()'
  methods in the WMI Object Viewer Control using a value passed in the
  'lCtxHandle' parameter as an object pointer.";
tag_summary = "This host is installed with Microsoft WMI Administrative Tools
  and is prone to multiple remote code execution vulnerabilities.

This NVT has been replaced by NVT secpod_ms11-027.nasl 
(OID:1.3.6.1.4.1.25623.1.0.900281).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801677");
  script_version("$Revision: 8296 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_bugtraq_id(45546);
  script_cve_id("CVE-2010-3973", "CVE-2010-4588");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft WMI Administrative Tools ActiveX Control Remote Code Execution Vulnerabilities");


  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42693");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/725596");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3301");
  script_xref(name : "URL" , value : "http://www.wooyun.org/bug.php?action=view&id=1006");
  exit(0);
}


exit(66); ## This NVT is deprecated as addressed in secpod_ms11-027.nasl

include("smb_nt.inc");
include("secpod_activex.inc");

## Confirm Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## CLSID
clsid = "{2745E5F5-D234-11D0-847A-00C04FD7BB08}";

## Check if Kill-Bit is set
if(is_killbit_set(clsid:clsid) == 0){
  security_message(0);
}
