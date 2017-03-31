###############################################################################
# OpenVAS Include File
#
# $Id: docker.inc 5107 2017-01-25 17:31:44Z mime $
#
# Functions for Docker
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software
# Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
# USA.
#
# $Revision: 5107 $
#
###############################################################################

function docker_build_all_containers_array()
{
  local_var name, ports, id, image, containers, co;

  type = 'lsc';
  containers =  get_kb_list( "docker/" + type + "/container/*/id" );

  if( ! containers ) return;

  foreach id ( containers )
  {
    state = get_kb_item( "docker/" + type + "/container/" + id  + "/state" );
    name  = get_kb_item( "docker/" + type + "/container/" + id  + "/name" );
    ports = get_kb_item( "docker/" + type + "/container/" + id  + "/ports" );
    image = get_kb_item( "docker/" + type + "/container/" + id  + "/image" );

    co[ id ] = make_array( "name",  name,
                           "id",    id,
                           "image", image,
                           "ports", ports
                           );
  }

  return co;
}

function docker_build_running_containers_array()
{
  local_var name, ports, id, image, containers, co, type;

  type = 'lsc';
  containers =  get_kb_list( "docker/" + type + "/container/*/id" );

  if( ! containers ) return;

  foreach id ( containers )
  {
    state = get_kb_item( "docker/" + type + "/container/" + id  + "/state" );

    if( state !~ "^Up " ) continue;

    name  = get_kb_item( "docker/" + type + "/container/" + id  + "/name" );
    ports = get_kb_item( "docker/" + type + "/container/" + id  + "/ports" );
    image = get_kb_item( "docker/" + type + "/container/" + id  + "/image" );

    co[ id ] = make_array( "name",  name,
                           "id",    id,
                           "image", image,
                           "ports", ports
                           );
  }

  return co;
}

