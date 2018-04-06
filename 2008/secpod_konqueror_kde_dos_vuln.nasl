###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_konqueror_kde_dos_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Konqueror in KDE Denial of Service Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow attacker to trigger the use of a deleted
  object within the HTMLTokenizer::scriptHandler() method and can cause a crash.";
tag_affected = "Konqueror in KDE version 3.5.10 or prior.";
tag_insight = "These flaws are due to,
  - improper handling of JavaScript document.load Function calls targeting
    the current document which can cause denial of service.
  - HTML parser in KDE Konqueror causes denial of service via a long attribute
    in HR element or a long BGCOLOR or BORDERCOLOR.";
tag_solution = "Upgrade to KDE Konqueror version 4.4.3 or later.
  For updates refer to http://www.kde.org/download";
tag_summary = "This host is running Konqueror and is prone to Denial of Service
  Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900417");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-4514", "CVE-2008-5712");
  script_bugtraq_id(31696);
  script_name("Konqueror in KDE Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6718");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32208");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Denial of Service");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

knqrName = find_file(file_name:"konqueror", file_path:"/", useregex:TRUE,
                     regexpar:"$", sock:sock);
foreach binaryName (knqrName)
{
  binaryName = chomp(binaryName);
  knqrVer= get_bin_version(full_prog_name:binaryName, version_argv:"-v",
                           ver_pattern:"Konqueror: ([0-9.]+)", sock:sock);
  if(knqrVer[1] != NULL)
  {
    # Grep for version 3.5.9 or prior
    if(version_is_less_equal(version:knqrVer[1], test_version:"3.5.9")){
      security_message(0);
    }
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();
