###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gb_hp_openview_nnm_41829.nasl 7765 2017-11-15 06:34:32Z cfischer $
#
# HP OpenView Network Node Manager 'execvp_nc()' Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:openview_network_node_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100786");
  script_version("$Revision: 7765 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-15 07:34:32 +0100 (Wed, 15 Nov 2017) $");
  script_tag(name:"creation_date", value:"2010-09-07 15:26:31 +0200 (Tue, 07 Sep 2010)");
  script_bugtraq_id(41829);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2703");
  script_name("HP OpenView Network Node Manager 'execvp_nc()' Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("os_detection.nasl", "secpod_hp_openview_nnm_detect.nasl");
  script_require_ports("Services/www", 7510);
  script_mandatory_keys("HP/OVNNM/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41829");
  script_xref(name:"URL", value:"http://www.exploit-db.com/moaub-6-hp-openview-nnm-webappmon-exe-execvp_nc-remote-code-execution/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/512543");
  script_xref(name:"URL", value:"http://itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02286088");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-137/");

  tag_summary = "HP OpenView Network Node Manager (OV NNM) is prone to a remote
  code-execution vulnerability.";

  tag_impact = "An attacker can exploit this issue to execute arbitrary code with SYSTEM-
  level privileges. Successful exploits will completely compromise
  affected computers.";

  tag_affected = "The issue affects HP OpenView Network Node Manager versions 7.51 and
  7.53 running on the Windows platform.";

  tag_solution = "Updates are available. Please see the references for details.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
get_app_version( cpe:CPE, port:port, nofork:TRUE );
if( ! vers = get_kb_item( "www/"+ port + "/HP/OVNNM/Ver" ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"B.07.51" ) ||
    version_is_equal( version:vers, test_version:"B.07.53" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );