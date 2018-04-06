###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qqplayer_mov_file_bof_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# QQPlayer MOV File Processing Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012  Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to execution of
arbitrary code.

Impact Level: Application";

tag_affected = "QQPlayer version 3.2.845 and prior.";

tag_insight = "The flaw is due to a boundary error when processing MOV files,
Which can be exploited to cause a stack based buffer overflow by sending
specially crafted MOV file with a malicious PnSize value.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with QQPlayer and is prone to buffer
overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802367");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-5006");
  script_bugtraq_id(50739);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-02 12:43:57 +0530 (Mon, 02 Jan 2012)");
  script_name("QQPlayer MOV File Processing Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://1337day.com/exploits/16899");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46924");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71368");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18137/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get QQplayer path from Registry
qqplName = "SOFTWARE\Tencent\QQPlayer";
if(!registry_key_exists(key:qqplName)){
  exit(0);
}

qqplVer = registry_get_sz(key:qqplName, item:"Version");
if(qqplVer != NULL)
{
  ## Check for QQplayer version 3.2.845 (3.2.845.400)
  if(version_is_less_equal(version:qqplVer, test_version:"3.2.845.400")){
    security_message(0);
  }
}
