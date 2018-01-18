###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quiksoft_easymail_obj_activex_bof_vuln_mar10.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# Quiksoft EasyMail Objects AddAttachments() ActiveX Control BOF Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
features, remove the product or replace the product by another one.

A Workaround is to set the killbit for the following CLSID,
{68AC0D5F-0424-11D5-822F-00C04F6BA8D9}
http://support.microsoft.com/kb/240797";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application with elevated privileges or cause
  the browser to crash.
  Impact Level: Application";
tag_affected = "Quiksoft EasyMail Objects 6.0 on Windows";
tag_insight = "The flaw exists in AddAttachments() method, which fails to perform adequate
  boundary checks on user-supplied data.";
tag_summary = "This host is installed with QuikSoft EasyMail Objects ActiveX
  Control and is prone to Buffer Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800993");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4663");
  script_bugtraq_id(36440);
  script_name("Quiksoft EasyMail Objects AddAttachments() ActiveX Control BOF Vulnerability");

  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9705");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53325");
  script_xref(name : "URL" , value : "http://www.bmgsec.com.au/advisories/easymail-6-activex-exploit.txt");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_activex.inc");

## Check for Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm EasyMail Objects 6.0 installed by checking below registry key
key = "SOFTWARE\Quiksoft Corporation\EasyMail Objects\6.0";
if(registry_key_exists(key:key))
{
  ## Workaround check
  if(is_killbit_set(clsid:"{68AC0D5F-0424-11D5-822F-00C04F6BA8D9}") == 0){
    security_message(0);
  }
}
