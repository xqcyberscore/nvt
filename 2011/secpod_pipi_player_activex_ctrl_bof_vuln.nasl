###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pipi_player_activex_ctrl_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# PIPI Player PIPIWebPlayer ActiveX Control Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary code in the context of the application.

Impact Level: Application.";

tag_affected = "PIPI Player version 2.8.0.0";

tag_insight = "The flaw is due to an error when processing the 'PlayURL()' and
'PlayURLWithLocalPlayer()' methods. This can be exploited to cause a
stack-based buffer overflow via an overly long string passed to the methods.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.

A workaround is to set the kill-bit for the affected ActiveX control.";

tag_summary = "This host is installed with PIPI Player and is prone to buffer
overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902346");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_cve_id("CVE-2011-1065");
  script_bugtraq_id(46468);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("PIPI Player PIPIWebPlayer ActiveX Control Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43394");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65537");
  script_xref(name : "URL" , value : "http://www.wooyun.org/bugs/wooyun-2010-01383");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

## Get Install Location From Registry
foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("PIPI" >< name)
  {
    ver = eregmatch(pattern:"PIPI ([0-9.]+)", string:name);
    if(ver[1] != NULL)
    {
      ## Check for PIPI Player version equal to 2.8.0.0
      if(version_is_equal(version:ver[1], test_version:"2.8.0.0")){
        security_message(0) ;
      }
    }
  }
}
