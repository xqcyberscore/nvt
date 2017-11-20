###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_registry_violation.nasl 7811 2017-11-17 11:52:16Z cfischer $
#
# Windows Registry Check: Violations
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
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

# kb: Keep above the description part as it is used there
include("gos_funcs.inc");
include("version_func.inc");
gos_version = get_local_gos_version();
if( strlen( gos_version ) > 0 &&
    version_is_greater_equal( version:gos_version, test_version:"4.2.4" ) ) {
  use_severity = TRUE;
}

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105990");
  script_version("$Revision: 7811 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-17 12:52:16 +0100 (Fri, 17 Nov 2017) $");
  script_tag(name:"creation_date", value:"2015-05-22 12:45:52 +0700 (Fri, 22 May 2015)");
  if( use_severity ) {
    script_tag(name:"cvss_base", value:"10.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  } else {
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  }
  script_name("Windows Registry Check: Violations");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("policy_registry.nasl");
  script_mandatory_keys("policy/registry/started");

  script_tag(name:"summary", value:"List registry entries which didn't pass the registry
  policy check.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

violations = get_kb_list( "policy/registry/violation_list" );

if( violations ) {

  # Sort to not report changes on delta reports if just the order is different
  violations = sort( violations );

  report  = 'The following registry entries did not pass the registry policy check:\n\n';
  report += 'Registry entry | Present | Value checked against | Value set in registry\n';

  foreach violation( violations ) {
    report += violation + '\n';
  }
  if( use_severity )
    security_message( port:0, data:report );
  else
    log_message( port:0, data:report );
}

exit( 0 );
