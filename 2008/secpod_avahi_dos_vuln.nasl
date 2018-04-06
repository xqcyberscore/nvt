###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_avahi_dos_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Avahi Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation could allow attackers to execute malicious arbitrary
  code or cause denial of service.
  Impact Level: System/Application";
tag_affected = "Avahi version prior to 0.6.24 on all Linux platforms.";
tag_insight = "This flaw is caused when processing multicast DNS data which causes
  the application to crash.";
tag_solution = "Upgrade to the latest version 0.6.24 or later,
  http://avahi.org/download";
tag_summary = "This host is installed with Avahi and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900415");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5081");
  script_bugtraq_id(32825);
  script_name("Avahi Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7520");
  script_xref(name : "URL" , value : "http://avahi.org/milestone/Avahi%200.6.24");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2008/12/14/1");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_avahi_detection_lin.nasl");
  script_mandatory_keys("Avahi/Linux/Ver");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

  exit(0);
}


include("version_func.inc");

avahiVer = get_kb_item("Avahi/Linux/Ver");
if(!avahiVer){
  exit(0);
}

# Grep for version 0.6.23 or prior
if(version_is_less_equal(version:avahiVer, test_version:"0.6.23")){
  security_message(0);
}
