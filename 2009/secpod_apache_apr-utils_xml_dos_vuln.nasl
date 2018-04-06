###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_apr-utils_xml_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Apache APR-Utils XML Parser Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Attackers can exploit these issues to crash the application
  resulting into a denial of service condition.
  Impact Level: Application";
tag_affected = "Apache APR-Utils version prior to 1.3.7 on Linux.";
tag_insight = "An error in the 'expat XML' parser when processing crafted XML documents
  containing a large number of nested entity references.";
tag_solution = "Apply the patch or upgrade to Apache APR-Utils 1.3.7
  http://apr.apache.org/download.cgi";
tag_summary = "The host is installed with Apache APR-Utils and is prone to
  Denial of Service Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900573");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1955");
  script_bugtraq_id(35253);
  script_name("Apache APR-Utils XML Parser Denial of Service Vulnerability");


  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_apache_apr-utils_detect.nasl");
  script_require_keys("Apache/APR-Utils/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.apache.org/dist/apr/CHANGES-APR-UTIL-1.3");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=rev&revision=781403");
  exit(0);
}


include("version_func.inc");

utilsVer = get_kb_item("Apache/APR-Utils/Ver");
if(!utilsVer){
  exit(0);
}

if(version_is_less(version:utilsVer, test_version:"1.3.7")){
  security_message(0);
}
