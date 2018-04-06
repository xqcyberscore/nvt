###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xampp_mult_csrf_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# XAMPP Multiple Cross-Site Request Forgery Vulnerability
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

tag_impact = "Successful exploitation will let the attacker execute crafted malicious
  queries in the vulnerable parameters or can change admin authentication data
  via crafted CSRF queries.
  Impact Level: Application/Network";
tag_affected = "XAMPP version 1.6.8 or prior on all platforms.";
tag_insight = "Multiple flaws are due to,
  - Lack of input validation checking for the user-supplied data provided
    to 'security/xamppsecurity.php' which lets change admin password through
    CSRF attack.
  - Input passed to some certain parameters like 'dbserver', 'host', 'password',
    'database' and 'table' in not properly sanitised before being returned to a
    user.";
tag_solution = "Upgrade to XAMPP version 1.7.3 or later,
  For updates refer to http://www.apachefriends.org/en/xampp.htm";
tag_summary = "The host is installed with XAMPP and is prone to multiple
  cross-site request forgery vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900527");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6498", "CVE-2008-6499");
  script_name("XAMPP Multiple Cross-Site Request Forgery Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32134");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7384");
  script_xref(name : "URL" , value : "http://securityreason.com/securityalert/5434");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_xampp_detect.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_mandatory_keys("xampp/installed");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("version_func.inc");
include("http_func.inc");

xamppPort = get_http_port( default:80 );

xamppVer = get_kb_item("www/" + xamppPort + "/XAMPP");
if(!xamppVer){
  exit(0);
}

if(version_is_less_equal(version:xamppVer, test_version:"1.6.8")){
  security_message(xamppPort);
}
