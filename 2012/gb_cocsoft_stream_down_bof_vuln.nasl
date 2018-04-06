###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cocsoft_stream_down_bof_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# CoCSoft Stream Down Buffer overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

Impact Level: System/Application";

tag_affected = "CoCSoft Stream Down version 6.8.0";

tag_insight = "The flaw is due to an unspecified error in the application, which
can be exploited to cause a heap-based buffer overflow.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with CoCSoft Stream Down and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802551");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-5052");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-02 16:06:04 +0530 (Mon, 02 Jan 2012)");
  script_name("CoCSoft Stream Down Buffer overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18283/");
  script_xref(name : "URL" , value : "http://dev.metasploit.com/redmine/issues/6168");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item(registry_enum_keys(key:key))
{
  cocName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check DisplayName for CoCSoft StreamDown
  if("StreamDown" >< cocName)
  {
    ## Get CoCSoft StreamDown version
    cocVer = eregmatch(pattern:"[0-9.]+", string:cocName);
    if(cocVer[0]!= NULL)
    {
      ## Check for CoCSoft StreamDown version
      if(version_is_equal(version:cocVer[0], test_version:"6.8.0"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
