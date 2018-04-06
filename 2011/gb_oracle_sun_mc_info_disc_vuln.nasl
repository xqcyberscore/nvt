###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_sun_mc_info_disc_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Oracle Sun Management Center Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "Apply the security updates.
  http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to affect confidentiality
  and integrity via unknown vectors.
  Impact Level: System/Application";
tag_affected = "Oracle SunMC version 4.0";
tag_insight = "The issue is caused by an unknown error within the Web Console component,
  which could allow attackers to disclose certain information.";
tag_summary = "The host is installed with Oracle Sun Management Center and is
  prone to information disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801587");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_cve_id("CVE-2010-4436");
  script_bugtraq_id(45885);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Oracle Sun Management Center Information Disclosure Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/42989");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64814");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0156");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check related key
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sun Management Center\";

## if key does not exist, exit
if(!registry_key_exists(key:key)){
  exit(0);
}

smcName = registry_get_sz(key:key, item:"DisplayName");

## Confirm the applcation with name
if("Sun Management Center" >< smcName)
{
  smcVer = registry_get_sz(key:key, item:"BaseProductDirectory");

  ## check for the version
  if(smcVer == "SunMC4.0"){
    security_message(0);
  }
}
