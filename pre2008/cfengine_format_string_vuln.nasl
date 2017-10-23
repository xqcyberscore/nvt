###############################################################################
# OpenVAS Vulnerability Test
# $Id: cfengine_format_string_vuln.nasl 7529 2017-10-20 10:53:04Z cfischer $
#
# cfengine format string vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
###############################################################################

# Ref: Pekka Savola <pekkas@netcore.fi>

CPE = "cpe:/a:gnu:cfengine";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14316");
  script_version("$Revision: 7529 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-20 12:53:04 +0200 (Fri, 20 Oct 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1757);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2000-0947");
  script_name("cfengine format string vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Gain a shell remotely");
  script_dependencies("cfengine_detect.nasl");
  script_mandatory_keys("cfengine/running");

  tag_summary = "Cfengine is running on this remote host.

  Cfengine contains a component, cfd, which serves as a remote-configuration
  client to cfengine. This version of cfd contains several flaws in the
  way that it calls syslog(). As a result, trusted hosts and valid users
  (if access controls are not in place) can cause the vulnerable host to
  log malicious data which, when logged, can either crash the server or
  execute arbitrary code on the stack. In the latter case, the code would
  be executed as the 'root' user.";

  tag_solution = "Upgrade to 1.6.0a11 or newer";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_is_less( version:version, test_version:"1.6.0a11" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.6.0a11" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );