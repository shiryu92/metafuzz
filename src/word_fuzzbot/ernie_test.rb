require 'rubygems'
require 'ernie'

module Ext
  def add(a, b)
    a + b
  end
end

Ernie.expose(:ext, Ext)

