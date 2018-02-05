###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_x509_cert_spoofing_vuln_lin.nasl 8649 2018-02-03 12:16:43Z teissa $
#
# Opera 'X.509' Certificates Spoofing Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to spoof servers and
  obtain sensitive information.
  Impact Level: Application";
tag_affected = "Opera version prior to 9.63 on Linux";
tag_insight = "The flaw is due to an error in handling of certificates, It does not properly
  verify 'X.509' certificates from SSL servers.";
tag_solution = "Upgrade to Opera 9.63 or later,
  For updates refer to http://www.opera.com/";
tag_summary = "The host is installed with Opera and is prone to spoofing
  vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802436");
  script_version("$Revision: 8649 $");
  script_cve_id("CVE-2012-1251");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-06-12 16:15:21 +0530 (Tue, 12 Jun 2012)");
  script_name("Opera 'X.509' Certificates Spoofing Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN39707339/index.html");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/unix/963/");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000049.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_require_keys("Opera/Linux/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = "";

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

# Check for opera version is less than 9.63
if(version_is_less(version:operaVer, test_version:"9.63")){
  security_message(0);
}
