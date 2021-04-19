# Keep in mind that some combinations will not work together
option(ENABLE_SANITIZER_ADDRESS "Enable address sanitizer to detect memory violations, buffer overflows, memory leaks" OFF)
option(ENABLE_SANITIZER_LEAK "Enable leak sanitizer to detect memory leaks" OFF)
option(ENABLE_SANITIZER_MEMORY "Enable memory sanitizer to detect reads in unitialized memory" OFF)
option(ENABLE_SANITIZER_UNDEFINED "Enable undefined sanitizer to detect undefined behavior" OFF)
option(ENABLE_SANITIZER_THREAD "Enable thread sanitizer to detect data races" OFF)

set(ENABLED_SANITIZERS)
mark_as_advanced(ENABLED_SANITIZERS)

macro(add_sanitizer_option variable flag)
  if(${variable})
    list(APPEND ENABLED_SANITIZERS ${flag})
  endif()
endmacro()

add_sanitizer_option(ENABLE_SANITIZER_ADDRESS "address")
add_sanitizer_option(ENABLE_SANITIZER_LEAK "leak")
add_sanitizer_option(ENABLE_SANITIZER_MEMORY "memory")
add_sanitizer_option(ENABLE_SANITIZER_UNDEFINED "undefined")
add_sanitizer_option(ENABLE_SANITIZER_THREAD "thread")

function(enable_sanitizers target)
  if(ENABLED_SANITIZERS)
    string(REPLACE ";" "," enabled_sanitizer_flags "${ENABLED_SANITIZERS}")
    message(STATUS "Enabled ${enabled_sanitizer_flags} sanitizers on ${target}")


    target_compile_options(${target} PRIVATE
      $<$<CXX_COMPILER_ID:MSVC>:-fsanitize=${enabled_sanitizer_flags}>
      $<$<CXX_COMPILER_ID:Clang>:-g>
      $<$<CXX_COMPILER_ID:GNU>:-g>
      )

    target_link_libraries(${target} PRIVATE
      $<$<CXX_COMPILER_ID:Clang>:-fsanitize=${enabled_sanitizer_flags}>
      $<$<CXX_COMPILER_ID:GNU>:-fsanitize=${enabled_sanitizer_flags}>
      )

    target_link_options(${target} PRIVATE
      # Until version 16.9 Preview 2 of Visual Studio, we need to link manually against the asan libs
      # https://devblogs.microsoft.com/cppblog/addresssanitizer-asan-for-windows-with-msvc/#compiling-with-asan-from-the-console
      $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<VERSION_LESS_EQUAL:$ENV{VSCMD_VER},16.9.2>>:/wholearchive:clang_rt.asan_dynamic_runtime_thunk-x86_64.lib /wholearchive:clang_rt.asan_dynamic-x86_64.lib>
      )

  endif()
endfunction()
