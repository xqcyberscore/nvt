# OpenVAS Vulnerability Test
# $Id: libpng_CB-A08-0064.nasl 7784 2017-11-16 08:42:29Z cfischer $
# Description: libpng vulnerability
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote host is probably affected by the vulnerabilities described in
CVE-2008-1382

Impact
      libpng 1.0.6 through 1.0.32, 1.2.0 through 1.2.26,
      and 1.4.0beta01 through 1.4.0beta19 allows context-dependent
      attackers to cause a denial of service (crash) and possibly
      execute arbitrary code via a PNG file with zero length
      unknown chunks, which trigger an access of uninitialized
      memory.";

tag_solution = "All users should upgrade to the latest libpng version of their Linux Distribution.";

# $Revision: 7784 $

if(description)
{

 script_id(90021);
 script_version("$Revision: 7784 $");
 script_tag(name:"last_modification", value:"$Date: 2017-11-16 09:42:29 +0100 (Thu, 16 Nov 2017) $");
 script_tag(name:"creation_date", value:"2008-09-03 22:30:27 +0200 (Wed, 03 Sep 2008)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-1382");
 name = "libpng vulnerability";
 script_name(name);

 summary = "Determines the Version of libpng";
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
 script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
 family = "General";
 script_family(family);
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);

  # This NVT is broken in many ways...
  script_tag(name:"deprecated", value:TRUE);

 exit(0);
}

exit( 66 );

include("ssh_func.inc");
include("version_func.inc");

local_var r;

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

r = find_bin(prog_name:"libpng-config", sock:sock);
foreach binary_name (r) {
  binary_name = chomp(binary_name);
  ver = get_bin_version(full_prog_name:binary_name, version_argv:"--version", ver_pattern:"^([0-9.]+)$");
  if(ver != NULL) {
    if(version_is_less(version:ver[0], test_version:"1.0.32") ) {
      security_message(port:0);
      report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
      security_message(port:0, data:report);
    } else {
      if(version_is_greater_equal(version:ver[0], test_version:"1.2.0") &&
         version_is_less(version:ver[0], test_version:"1.2.27") ) {
        security_message(port:0);
        report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
        security_message(port:0, data:report);
      } else {
        if(version_is_equal(version:ver[0], test_version:"1.4.0") ) {
          ver = get_bin_version(full_prog_name:binary_name, version_argv:"--version", ver_pattern:"(beta..)");
          if(ver != NULL) {
            if(version_is_greater_equal(version:ver[0], test_version:"beta01") && 
               version_is_less(version:ver[0], test_version:"beta20") ) {
              security_message(port:0);
              report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
              security_message(port:0, data:report);
            }
          }
        }
      }
    }
  }
}

exit(0);
