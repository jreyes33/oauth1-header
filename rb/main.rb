# frozen_string_literal: true

require 'ffi'

module OAuthFFI
  extend FFI::Library
  LIB_PATH = "../target/release/liboauth1_header.#{FFI::Platform::LIBSUFFIX}"
  ffi_lib File.expand_path(LIB_PATH, __dir__)
  attach_function :auth_header,
                  %i[string string string string string string pointer size_t],
                  :string
end

def hash_to_ptr(hash)
  params_arr = hash.flatten.map { |p| FFI::MemoryPointer.from_string(p.to_s) }
  arr_ptr = FFI::MemoryPointer.new(FFI::MemoryPointer.size, params_arr.length)
  arr_ptr.write_array_of_pointer(params_arr)
end

def auth_header
  params = { foo: 'bar', a: 1, b: true }
  OAuthFFI.auth_header(
    'some-consumer-key',
    'some-consumer-secret',
    'some-token',
    'some-token-secret',
    'GET',
    'https://example.com',
    hash_to_ptr(params),
    params.length * 2
  )
end

require 'benchmark'

LABEL = 'ffi from ruby'
Benchmark.bm(LABEL.length) do |b|
  b.report(LABEL) { 500_000.times { auth_header } }
end
