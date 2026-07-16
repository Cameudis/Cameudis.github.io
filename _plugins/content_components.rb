# frozen_string_literal: true

require "uri"

module Jekyll
  module ContentComponents
    CALLOUT_TYPES = %w[note tip warning danger important].freeze
    MARKDOWN_EXTENSIONS = %w[.md .markdown].freeze

    class Transformer
      CALLOUT_START = /\A(?<indent> {0,3})>\s*\[!(?<type>[A-Za-z][A-Za-z0-9_-]*)\](?:[ \t]+(?<title>.*?))?[ \t]*(?:\r?\n)?\z/
      AUTOLINK = /\A {0,3}<(?<url>https?:\/\/[^<>\s]+)>[ \t]*(?:\r?\n)?\z/i
      FENCE_START = /\A {0,3}(?<fence>`{3,}|~{3,})/
      LIQUID_LITERAL_START = /\A\s*\{%\s*(?<name>raw|comment|highlight)\b/
      LIQUID_LITERAL_END = /\A\s*\{%\s*end(?<name>raw|comment|highlight)\s*%\}/

      def initialize
        @component_id = 0
      end

      def transform(content)
        transform_lines(content.to_s.lines).join
      end

      private

      def transform_lines(lines)
        output = []
        index = 0
        fence = nil
        liquid_literal = nil

        while index < lines.length
          line = lines[index]

          if liquid_literal
            output << line
            liquid_literal = nil if liquid_literal_end?(line, liquid_literal)
            index += 1
            next
          end

          if fence
            output << line
            fence = nil if fence_end?(line, fence)
            index += 1
            next
          end

          if (literal_match = line.match(LIQUID_LITERAL_START))
            liquid_literal = literal_match[:name]
            output << line
            index += 1
            next
          end

          if (fence_match = line.match(FENCE_START))
            fence = fence_match[:fence]
            output << line
            index += 1
            next
          end

          if (callout_match = line.match(CALLOUT_START))
            block_lines, next_index = consume_callout(lines, index, callout_match[:indent])
            output << render_callout(
              callout_match[:type],
              callout_match[:title],
              block_lines
            )
            index = next_index
            next
          end

          if (autolink_match = line.match(AUTOLINK))
            output << render_card(autolink_match[:url])
            index += 1
            next
          end

          output << line
          index += 1
        end

        output
      end

      def consume_callout(lines, start_index, indent)
        body = []
        index = start_index + 1
        quote_line = /\A#{Regexp.escape(indent)}> ?(?<content>.*?)(?<newline>\r?\n)?\z/

        while index < lines.length
          match = lines[index].match(quote_line)
          break unless match

          body << "#{match[:content]}#{match[:newline]}"
          index += 1
        end

        [body, index]
      end

      def render_callout(type, title, body_lines)
        component_id = next_component_id
        canonical_type = CALLOUT_TYPES.include?(type.downcase) ? type.downcase : "note"
        body_variable = "__content_component_callout_#{component_id}"
        transformed_body = transform_lines(body_lines).join
        title_markup = ""
        title_argument = ""

        unless title.to_s.empty?
          title_variable = "__content_component_callout_title_#{component_id}"
          title_markup = "{% capture #{title_variable} %}#{title}{% endcapture %}\n"
          title_argument = " title=#{title_variable}"
        end

        <<~LIQUID
          #{title_markup}{% capture #{body_variable} %}
          #{transformed_body}{% endcapture %}
          {% include callout.html type="#{canonical_type}"#{title_argument} content=#{body_variable} %}
        LIQUID
      end

      def render_card(url)
        component_id = next_component_id
        value_variable = "__content_component_card_#{component_id}"
        repo = github_repository(url)
        include_markup = if repo
                           "{% include github_repo.html repo=#{value_variable} %}"
                         else
                           "{% include link_preview.html url=#{value_variable} %}"
                         end

        <<~LIQUID
          {% capture #{value_variable} %}#{repo || url}{% endcapture %}
          #{include_markup}
        LIQUID
      end

      def github_repository(url)
        uri = URI.parse(url)
        return unless %w[github.com www.github.com].include?(uri.host&.downcase)
        return if uri.query || uri.fragment

        match = uri.path.match(%r{\A/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?\z})
        "#{match[1]}/#{match[2]}" if match
      rescue URI::InvalidURIError
        nil
      end

      def next_component_id
        @component_id += 1
      end

      def fence_end?(line, fence)
        line.match?(/\A {0,3}#{Regexp.escape(fence[0])}{#{fence.length},}[ \t]*(?:\r?\n)?\z/)
      end

      def liquid_literal_end?(line, name)
        match = line.match(LIQUID_LITERAL_END)
        match && match[:name] == name
      end
    end

    module_function

    def transform_document(document)
      extension = File.extname(document.path.to_s).downcase
      return unless MARKDOWN_EXTENSIONS.include?(extension)

      document.content = Transformer.new.transform(document.content)
    end
  end
end

Jekyll::Hooks.register :documents, :pre_render do |document|
  Jekyll::ContentComponents.transform_document(document)
end

Jekyll::Hooks.register :pages, :pre_render do |page|
  Jekyll::ContentComponents.transform_document(page)
end
