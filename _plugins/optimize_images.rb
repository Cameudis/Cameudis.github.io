# frozen_string_literal: true

module Jekyll
  module OptimizeImages
    def optimize_images(html)
      html.to_s.gsub(/<img\b[^>]*>/i) do |tag|
        attributes = []
        attributes << ' loading="lazy"' unless tag.match?(/\bloading\s*=/i)
        attributes << ' decoding="async"' unless tag.match?(/\bdecoding\s*=/i)
        tag.sub(/\A<img\b/i, "<img#{attributes.join}")
      end
    end
  end
end

Liquid::Template.register_filter(Jekyll::OptimizeImages)
