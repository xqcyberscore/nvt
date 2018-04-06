###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_html_form_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Internet Explorer HTML Form Value DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
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

tag_impact = "Successful exploitation could allow remote attackers to crash the browser.
  Impact Level: Application";
tag_affected = "Microsoft Internet Explorer version 7.0 and prior on Windows.";
tag_insight = "Browser fails to validate user supplied data via a long VALUE attribute in
  an INPUT element.";
tag_solution = "No solution or patch was made available for at least one year since disclosure
  of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.
  For updates refer to http://www.microsoft.com/windows/internet-explorer/download-ie.aspx";
tag_summary = "This host is installed Internet Explorer and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900303");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-03 15:40:18 +0100 (Tue, 03 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0341");
  script_bugtraq_id(33494);
  script_name("Microsoft Internet Explorer HTML Form Value DoS Vulnerability");
  script_xref(name : "URL" , value : "http://jplopezy.fortunecity.es/ietest.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/500472/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

exit(0); ## plugin may results to Fp

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for Internet Explorer version 7.0 and prior
if(ieVer =~ "^[5-7]\..*"){
  security_message(0);
}
