##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_policy_docker_violation.nasl 7783 2017-11-16 08:20:50Z cfischer $
#
# Docker Compliance Check: Failed
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

# kb: Keep above the description part as it is used there
include("gos_funcs.inc");
include("version_func.inc");
gos_version = get_local_gos_version();
if( strlen( gos_version ) > 0 &&
    version_is_greater_equal( version:gos_version, test_version:"4.2.4" ) ) {
  use_severity = TRUE;
}

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140122");
  script_version("$Revision: 7783 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-16 09:20:50 +0100 (Thu, 16 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-01-19 10:35:52 +0100 (Thu, 19 Jan 2017)");
  if( use_severity ) {
    script_tag(name:"cvss_base", value:"10.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  } else {
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  }

  script_tag(name: "qod", value: "98");

  script_name("Docker Compliance Check: Failed");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_policy_docker.nasl");
  script_mandatory_keys("docker/docker_test/has_failed_tests","docker/docker_test/report_failed");

  script_tag(name: "summary", value: "Lists all the Docker Compliance Policy Checks which did NOT pass.");

  exit(0);
}

include("misc_func.inc");
include("docker.inc");
include("docker_policy.inc");
include("docker_policy_tests.inc");

if( ! f = get_kb_list("docker/docker_test/failed/*") ) exit( 0 );

failed_count = max_index( keys( f ) );

if( failed_count == 0 )
  exit( 0 );

report = failed_count + ' Checks failed:\n\n';

foreach failed ( sort( keys( f ) ) )
{
  _id = eregmatch( pattern:'docker/docker_test/failed/([0-9.]+)', string:failed );
  if( isnull( _id[1] ) )
    continue;

  id = _id[1];
  reason = chomp( f[ failed ] );

  data = get_docker_test_data( id:id );

  report += ' - ' + data['title'] + '\n\nDescription: ' +  data['desc'] + '\n' + 'Solution: ' + data['solution'] + '\n\n' + 'Result: ' + reason + '\n\n';
}

if( use_severity )
  security_message( port:0, data:report );
else
  log_message( port:0, data:report );

exit( 0 );
