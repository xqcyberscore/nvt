# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later # See https://spdx.org/licenses/
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113350");
  script_version("$Revision: 14057 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:02:00 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-06 13:15:32 +0100 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Schneider Electric InduSoft Web Studio Detection (Consolidation)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_indusoft_web_studio_detect_win.nasl", "gb_schneider_indusoft_http_detect.nasl");
  script_mandatory_keys("schneider_indusoft/installed");

  script_tag(name:"summary", value:"Reports on findings if an installation of
  Schneider Electric Indusoft Web Studio has been found on the target system.");

  script_xref(name:"URL", value:"http://www.indusoft.com/");

  exit(0);
}

CPE = "cpe:/a:schneider_electric:indusoft_web_studio:";

include( "host_details.inc" );
include( "cpe.inc" );

version = "unknown";

extra = 'Concluded from:';
concluded = "";


foreach proto ( make_list( "smb", "http" ) ) {
  if( ! get_kb_item( "schneider_indusoft/" + proto + "/detected" ) ) continue;
  if( ( ver = get_kb_item( "schneider_indusoft/" + proto + "/version" ) )  && ver != "unknown" ) {
    concl = get_kb_item( "schneider_indusoft/" + proto + "/concluded" );
    extra += '\n\n' + toupper( proto ) + ':\n' + concl;
    if( version == "unknown" )
      version = ver;
    if( concluded == "")
      concluded = toupper( proto );
    else
      concluded += ", " + toupper( proto );
  }
}

regPort = get_kb_item( "schneider_indusoft/http/port" );
conclUrl = get_kb_item( "schneider_indusoft/http/location" );
insloc = get_kb_item( "schneider_indusoft/smb/location" );

register_and_report_cpe( app: "Schneider Electric InduSoft Web Studio",
                         ver: version,
                         concluded: concluded,
                         base: CPE,
                         expr: '([0-9.]+)',
                         insloc: insloc,
                         regPort: regPort,
                         regProto: concluded,
                         conclUrl: conclUrl,
                         extra: extra );

exit( 0 );
