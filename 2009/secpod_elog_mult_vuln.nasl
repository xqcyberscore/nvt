###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_elog_mult_vuln.nasl 5055 2017-01-20 14:08:39Z teissa $
#
# ELOG Remote Buffer Overflow and Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary scripting
  code, cause a denial of service or compromise a vulnerable system.
  Impact Level: System/Application";
tag_affected = "ELOG versions prior to 2.7.1";
tag_insight = "The flaws are due to:
  - A buffer overflow error in 'elog.c' when processing malformed data.
  - An infinite loop in the 'replace_inline_img()' [elogd.c] function.
  - An input validation error when handling the 'subtext' parameter.";
tag_solution = "Upgrade ELOG Version to 2.7.1
  For updates refer to https://midas.psi.ch/elog/download/";
tag_summary = "This host has ELOG installed and is prone multiple vulnerabilities.";

if(description)
{
  script_id(901009);
  script_version("$Revision: 5055 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-20 15:08:39 +0100 (Fri, 20 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7004", "CVE-2008-0444", "CVE-2008-0445");
  script_bugtraq_id(27399);
  script_name("ELOG Remote Buffer Overflow and Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/39903");
  script_xref(name : "URL" , value : "https://midas.psi.ch/elog/download/ChangeLog");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/0265");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_elog_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

elogPort = get_http_port(default:8080);
if(!elogPort){
  exit(0);
}

elogVer = get_kb_item("www/" + elogPort + "/ELOG");
if(elogVer != NULL)
{
  # Check for ELOG versions prior to 2.7.1 => 2.7.1.2002
  if(version_is_less(version:elogVer, test_version:"2.7.1.2002")){
   security_message(elogPort);
  }
}
